import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import apiClient from '../api/client.js';
import './AdminSettings.css';
import './AdminMobileOptimizations.css';

const TEXT = {
  title: 'Налаштування системи',
  subtitle: 'Керуйте параметрами застосунку, безпекою та поведінкою талонів.',
  searchPlaceholder: 'Пошук налаштувань...',
  loading: 'Завантаження налаштувань...',
  nothingFound: 'Нічого не знайдено за вашим запитом.',
  noSettingsCategory: 'У цій категорії немає налаштувань.',
  selectCategory: 'Оберіть категорію зліва, щоб переглянути налаштування.',
  noChanges: 'Немає змін для збереження.',
  saveSuccess: 'Зміни успішно збережено.',
  backupSuccess: 'Бекап налаштувань успішно завантажено.',
  restoreSuccess: 'Налаштування відновлено з файлу.',
  resetSuccess: 'Налаштування скинуто до стандартних значень.',
  loadError: 'Не вдалося завантажити налаштування.',
  saveError: 'Не вдалося зберегти налаштування.',
  backupError: 'Не вдалося створити бекап.',
  restoreError: 'Не вдалося відновити налаштування.',
  resetError: 'Не вдалося скинути налаштування.',
  changedLabel: 'Змінено налаштувань',
  save: 'Зберегти',
  cancel: 'Скасувати зміни',
  refresh: 'Оновити',
  backup: 'Створити бекап',
  restore: 'Відновити з файлу',
  defaults: 'Скинути до стандартних',
  nonEditableHint: 'Це системний параметр тільки для читання.',
  restoreConfirm: 'Поточні налаштування будуть замінені даними з файлу. Продовжити?',
  resetConfirm: 'Скинути всі налаштування до стандартних значень?',
  reloadPage: 'Оновити сторінку'
};

function normalizeValueByType(value, type) {
  if (type === 'boolean') {
    return value === true || value === 'true' || value === '1' || value === 1;
  }

  if (type === 'number') {
    if (value === '' || value === null || value === undefined) return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return value === null || value === undefined ? '' : String(value);
}

function areValuesEqual(a, b, type) {
  if (type === 'number') {
    const left = normalizeValueByType(a, 'number');
    const right = normalizeValueByType(b, 'number');
    return left === right;
  }

  if (type === 'boolean') {
    return normalizeValueByType(a, 'boolean') === normalizeValueByType(b, 'boolean');
  }

  return normalizeValueByType(a, 'string') === normalizeValueByType(b, 'string');
}

function toApiValue(value, type) {
  if (type === 'boolean') {
    return normalizeValueByType(value, 'boolean') ? 'true' : 'false';
  }

  if (type === 'number') {
    const parsed = normalizeValueByType(value, 'number');
    if (parsed === null) {
      throw new Error('Числове поле не може бути порожнім');
    }
    return parsed;
  }

  return normalizeValueByType(value, 'string');
}

function formatRequestError(err, fallback) {
  const status = err?.response?.status;
  if (status === 401) return 'Сесія завершена. Увійдіть у систему знову.';
  if (status === 403) return 'Недостатньо прав для цієї дії.';
  if (!status && err?.message) return err.message;
  return fallback;
}

function AdminSettings() {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);
  const [changedSettings, setChangedSettings] = useState({});
  const [activeCategory, setActiveCategory] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const restoreInputRef = useRef(null);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      const response = await apiClient.get('/api/admin/config');
      const data = response?.data;

      if (!data || typeof data !== 'object') {
        throw new Error('Invalid settings payload');
      }

      setSettings(data);
      setMessage(null);
    } catch (err) {
      setMessage({
        type: 'error',
        text: formatRequestError(err, TEXT.loadError)
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const filteredSettings = useMemo(() => {
    const query = String(searchTerm || '').trim().toLowerCase();
    if (!query) return settings;

    return Object.keys(settings || {}).reduce((acc, categoryKey) => {
      const categoryData = settings[categoryKey];
      if (!categoryData || !Array.isArray(categoryData.settings)) return acc;

      const visibleSettings = categoryData.settings.filter((setting) => {
        return (
          String(setting.label || '').toLowerCase().includes(query) ||
          String(setting.description || '').toLowerCase().includes(query) ||
          String(setting.key || '').toLowerCase().includes(query)
        );
      });

      if (visibleSettings.length > 0) {
        acc[categoryKey] = {
          ...categoryData,
          settings: visibleSettings
        };
      }

      return acc;
    }, {});
  }, [settings, searchTerm]);

  useEffect(() => {
    const keys = Object.keys(filteredSettings || {});

    if (keys.length === 0) {
      setActiveCategory(null);
      return;
    }

    if (!activeCategory || !filteredSettings[activeCategory]) {
      setActiveCategory(keys[0]);
    }
  }, [filteredSettings, activeCategory]);

  const categories = useMemo(() => Object.entries(filteredSettings || {}), [filteredSettings]);

  const visibleSettingsCount = useMemo(() => {
    return categories.reduce((sum, [, categoryData]) => sum + (categoryData.settings?.length || 0), 0);
  }, [categories]);

  const hasChanges = Object.keys(changedSettings).length > 0;
  const busy = loading || saving;

  const getCurrentValue = useCallback(
    (setting) => {
      const changed = changedSettings[setting.key];
      return changed ? changed.value : setting.value;
    },
    [changedSettings]
  );

  const handleSettingChange = useCallback((setting, nextValue) => {
    setChangedSettings((prev) => {
      const next = { ...prev };
      const originalValue = setting.value;

      if (areValuesEqual(originalValue, nextValue, setting.type)) {
        delete next[setting.key];
      } else {
        next[setting.key] = {
          value: nextValue,
          type: setting.type,
          min: setting.min,
          max: setting.max
        };
      }

      return next;
    });
  }, []);

  const saveSettings = async () => {
    if (!hasChanges) {
      setMessage({ type: 'info', text: TEXT.noChanges });
      return;
    }

    try {
      setSaving(true);

      const payload = Object.entries(changedSettings).map(([key, item]) => {
        const value = toApiValue(item.value, item.type);

        if (item.type === 'number') {
          if (item.min !== undefined && value < item.min) {
            throw new Error(`Значення для "${key}" має бути не менше ${item.min}`);
          }
          if (item.max !== undefined && value > item.max) {
            throw new Error(`Значення для "${key}" має бути не більше ${item.max}`);
          }
        }

        return {
          key,
          type: item.type,
          value
        };
      });

      const response = await apiClient.post('/api/admin/config/bulk-update', {
        settings: payload
      });

      const updatedCount = response?.data?.updated?.length || 0;
      const failed = response?.data?.errors || [];

      if (failed.length === 0) {
        setMessage({
          type: 'success',
          text: `${TEXT.saveSuccess} Оновлено: ${updatedCount}.`
        });
        setChangedSettings({});
        await loadSettings();
      } else {
        const failedKeys = new Set(failed.map((item) => item.key));
        setChangedSettings((prev) => Object.fromEntries(Object.entries(prev).filter(([key]) => failedKeys.has(key))));
        setMessage({
          type: 'warning',
          text: `Частково збережено. Успішно: ${updatedCount}, помилок: ${failed.length}.`
        });
        if (updatedCount > 0) {
          await loadSettings();
        }
      }
    } catch (err) {
      setMessage({
        type: 'error',
        text: formatRequestError(err, TEXT.saveError)
      });
    } finally {
      setSaving(false);
    }
  };

  const resetChanges = () => {
    setChangedSettings({});
    setMessage(null);
  };

  const backupSettings = async () => {
    try {
      const response = await apiClient.get('/api/admin/config/backup/download');
      const backup = response?.data || {};
      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `settings-backup-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      setMessage({ type: 'success', text: TEXT.backupSuccess });
    } catch (err) {
      setMessage({
        type: 'error',
        text: formatRequestError(err, TEXT.backupError)
      });
    }
  };

  const restoreFromBackup = async (file) => {
    try {
      const rawText = await file.text();
      const parsed = JSON.parse(rawText);

      const currentValues = parsed.currentValues || parsed.values;
      const schema = parsed.settings || parsed.schema || parsed.defaults;

      if (!currentValues && !schema) {
        throw new Error('Некоректний формат бекапу');
      }

      setSaving(true);
      const payload = {};
      if (currentValues && typeof currentValues === 'object') payload.currentValues = currentValues;
      if (schema && typeof schema === 'object') payload.settings = schema;

      const response = await apiClient.post('/api/admin/config/restore', payload);

      setChangedSettings({});
      const restoredCount = Number(response?.data?.restored);
      setMessage({
        type: 'success',
        text: Number.isFinite(restoredCount)
          ? `${TEXT.restoreSuccess} Відновлено: ${restoredCount}.`
          : TEXT.restoreSuccess
      });
      await loadSettings();
    } catch (err) {
      setMessage({
        type: 'error',
        text: formatRequestError(err, TEXT.restoreError)
      });
    } finally {
      setSaving(false);
    }
  };

  const handleRestoreFileChange = (event) => {
    const file = event.target.files?.[0];
    event.target.value = '';

    if (!file) return;

    if (!window.confirm(TEXT.restoreConfirm)) {
      return;
    }

    restoreFromBackup(file);
  };

  const resetToDefaults = async () => {
    if (!window.confirm(TEXT.resetConfirm)) {
      return;
    }

    try {
      setSaving(true);
      const response = await apiClient.post('/api/admin/config/reset-to-defaults', {});
      setChangedSettings({});
      const resetCount = Number(response?.data?.reset);
      setMessage({
        type: 'success',
        text: Number.isFinite(resetCount)
          ? `${TEXT.resetSuccess} Скинуто: ${resetCount}.`
          : TEXT.resetSuccess
      });
      await loadSettings();
    } catch (err) {
      setMessage({
        type: 'error',
        text: formatRequestError(err, TEXT.resetError)
      });
    } finally {
      setSaving(false);
    }
  };

  const updateTooltipPosition = (event) => {
    const icon = event.currentTarget;
    const rect = icon.getBoundingClientRect();

    if (rect.left < 160) {
      icon.setAttribute('data-position', 'right');
      return;
    }

    if (rect.right > window.innerWidth - 160) {
      icon.setAttribute('data-position', 'left');
      return;
    }

    icon.setAttribute('data-position', 'center');
  };

  const renderSettingInput = (setting) => {
    const current = getCurrentValue(setting);
    const disabled = setting.editable === false;
    const inputId = `setting-${setting.key}`;

    if (setting.type === 'boolean') {
      return (
        <label className="setting-checkbox" htmlFor={inputId}>
          <input
            id={inputId}
            type="checkbox"
            checked={normalizeValueByType(current, 'boolean')}
            onChange={(event) => handleSettingChange(setting, event.target.checked)}
            disabled={disabled}
          />
        </label>
      );
    }

    if (setting.type === 'select') {
      const options = Array.isArray(setting.options) ? setting.options : [];
      return (
        <select
          id={inputId}
          className="setting-input"
          value={current ?? ''}
          onChange={(event) => handleSettingChange(setting, event.target.value)}
          disabled={disabled}
        >
          {options.map((option) => {
            const optionValue = typeof option === 'object' ? option.value : option;
            const optionLabel = typeof option === 'object' ? option.label || option.value : option;
            return (
              <option key={String(optionValue)} value={optionValue}>
                {optionLabel}
              </option>
            );
          })}
        </select>
      );
    }

    if (setting.type === 'textarea') {
      return (
        <textarea
          id={inputId}
          className="setting-input"
          rows={4}
          value={current ?? ''}
          onChange={(event) => handleSettingChange(setting, event.target.value)}
          disabled={disabled}
        />
      );
    }

    if (setting.type === 'number') {
      return (
        <input
          id={inputId}
          type="number"
          className="setting-input"
          value={current ?? ''}
          min={setting.min}
          max={setting.max}
          step={setting.step || 1}
          onChange={(event) => handleSettingChange(setting, event.target.value)}
          disabled={disabled}
        />
      );
    }

    return (
      <input
        id={inputId}
        type="text"
        className="setting-input"
        value={current ?? ''}
        placeholder={setting.default ? String(setting.default) : ''}
        onChange={(event) => handleSettingChange(setting, event.target.value)}
        disabled={disabled}
      />
    );
  };

  const activeCategoryData = activeCategory ? filteredSettings[activeCategory] : null;

  if (loading && Object.keys(settings).length === 0) {
    return (
      <div className="admin-settings loading">
        <p>{TEXT.loading}</p>
      </div>
    );
  }

  if (!loading && Object.keys(settings).length === 0) {
    return (
      <div className="admin-settings">
        <div className="message message-error">
          {TEXT.loadError}
          <button type="button" onClick={() => window.location.reload()} className="message-close" title={TEXT.reloadPage}>
            ↻
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-settings">
      <div className="settings-wrapper">
        <div className="settings-header">
          <div className="settings-header-copy">
            <h2>{TEXT.title}</h2>
            <p className="settings-subtitle">{TEXT.subtitle}</p>
          </div>
          <div className="settings-search">
            <input
              type="text"
              className="search-input"
              placeholder={TEXT.searchPlaceholder}
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
            />
          </div>
        </div>

        {message && (
          <div className={`message message-${message.type}`}>
            {message.text}
            <button type="button" onClick={() => setMessage(null)} className="message-close" title="Закрити">
              ✕
            </button>
          </div>
        )}

        <div className="settings-container">
          <aside className="settings-categories">
            {categories.length === 0 ? (
              <p className="no-categories">{TEXT.nothingFound}</p>
            ) : (
              categories.map(([categoryKey, categoryData]) => (
                <button
                  type="button"
                  key={categoryKey}
                  className={`category-btn ${activeCategory === categoryKey ? 'active' : ''}`}
                  onClick={() => setActiveCategory(categoryKey)}
                >
                  <span className="category-main">
                    {categoryData.icon ? `${categoryData.icon} ` : ''}
                    {categoryData.category || categoryKey}
                  </span>
                  <span className="setting-count">{categoryData.settings?.length || 0}</span>
                </button>
              ))
            )}
          </aside>

          <section className="settings-content">
            {activeCategoryData ? (
              <>
                <h3>{activeCategoryData.category || activeCategory}</h3>
                <p className="settings-subtitle-line">Налаштувань у вибраній категорії: {activeCategoryData.settings?.length || 0}</p>

                <div className="settings-list">
                  {(activeCategoryData.settings || []).length === 0 ? (
                    <p className="no-settings">{TEXT.noSettingsCategory}</p>
                  ) : (
                    activeCategoryData.settings.map((setting) => {
                      const isChanged = Object.prototype.hasOwnProperty.call(changedSettings, setting.key);

                      return (
                        <div key={setting.key} className={`setting-item ${isChanged ? 'changed' : ''}`}>
                          <div className="setting-label">
                            <label htmlFor={`setting-${setting.key}`}>{setting.label || setting.key}</label>
                            <span className="setting-key">{setting.key}</span>
                            {isChanged && <span className="changed-indicator">Змінено</span>}
                          </div>

                          {setting.description && <p className="setting-description">{setting.description}</p>}

                          <div className="setting-value">
                            {renderSettingInput(setting)}
                            {setting.min !== undefined && setting.max !== undefined && (
                              <span className="setting-range">Діапазон: {setting.min} - {setting.max}</span>
                            )}
                          </div>

                          {(setting.help || setting.description) && (
                            <div className="setting-help-row">
                              <span
                                className="help-icon"
                                tabIndex={0}
                                data-tooltip={setting.help || setting.description}
                                aria-label={setting.help || setting.description}
                                onMouseEnter={updateTooltipPosition}
                                onFocus={updateTooltipPosition}
                              >
                                ?
                              </span>
                            </div>
                          )}

                          {setting.editable === false && <p className="setting-hint">{TEXT.nonEditableHint}</p>}
                        </div>
                      );
                    })
                  )}
                </div>
              </>
            ) : (
              <div className="settings-content-empty">
                <p>{categories.length === 0 ? TEXT.nothingFound : TEXT.selectCategory}</p>
              </div>
            )}
          </section>
        </div>

        <div className="settings-actions">
          <div className="changes-info">
            {hasChanges ? (
              <p className="changes-count">
                {TEXT.changedLabel}: <strong>{Object.keys(changedSettings).length}</strong>
              </p>
            ) : (
              <p className="changes-count muted">Всі зміни збережені</p>
            )}
          </div>

          <div className="action-buttons">
            <button type="button" className="btn btn-primary" onClick={saveSettings} disabled={!hasChanges || busy}>
              {TEXT.save}
            </button>
            <button type="button" className="btn btn-secondary" onClick={resetChanges} disabled={!hasChanges || busy}>
              {TEXT.cancel}
            </button>
            <button type="button" className="btn btn-info" onClick={loadSettings} disabled={busy}>
              {TEXT.refresh}
            </button>
          </div>

          <div className="backup-buttons">
            <button type="button" className="btn btn-warning" onClick={backupSettings} disabled={busy}>
              {TEXT.backup}
            </button>
            <button type="button" className="btn btn-success" onClick={() => restoreInputRef.current?.click()} disabled={busy}>
              {TEXT.restore}
            </button>
            <button type="button" className="btn btn-danger" onClick={resetToDefaults} disabled={busy}>
              {TEXT.defaults}
            </button>
          </div>
        </div>

        <div className="settings-footer">
          <p className="footer-note">
            Порада: після критичних змін безпеки або системних параметрів перезапустіть бекенд-сервіс.
          </p>
          <p className="footer-note secondary">Показано налаштувань: {visibleSettingsCount}</p>
        </div>
      </div>

      <input
        ref={restoreInputRef}
        type="file"
        accept="application/json,.json"
        onChange={handleRestoreFileChange}
        style={{ display: 'none' }}
      />
    </div>
  );
}

export default AdminSettings;
