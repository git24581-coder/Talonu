import React, { useState, useEffect, useCallback } from 'react';
import apiClient from '../api/client.js';
import './AdminSettings.css';
import './AdminMobileOptimizations.css';

function AdminSettings() {
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState(null);
  const [changedSettings, setChangedSettings] = useState({});
  const [activeCategory, setActiveCategory] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Додати логіку для динамічного позиціонування tooltip'ю
  useEffect(() => {
    const handleTooltipPosition = () => {
      const helpIcons = document.querySelectorAll('.help-icon');
      helpIcons.forEach(icon => {
        const rect = icon.getBoundingClientRect();
        
        // Перевіримо, чи tooltip виходить за краї
        if (rect.left < 150) {
          icon.setAttribute('data-position', 'right');
        } else if (rect.right > window.innerWidth - 150) {
          icon.setAttribute('data-position', 'left');
        } else {
          icon.setAttribute('data-position', 'center');
        }
      });
    };

    // Виконати при монтуванні та при resize
    handleTooltipPosition();
    window.addEventListener('resize', handleTooltipPosition);
    return () => window.removeEventListener('resize', handleTooltipPosition);
  }, []);

  // Завантажити налаштування
  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      console.log('📥 Loading settings from API...');
      const response = await apiClient.get('/api/admin/config');
      console.log('✓ Settings loaded:', response.data);
      
      if (!response.data || typeof response.data !== 'object') {
        throw new Error('Invalid response format');
      }
      
      setSettings(response.data);
      
      setActiveCategory((prevCategory) => {
        if (prevCategory) return prevCategory;
        const firstCategory = Object.keys(response.data)[0] || null;
        if (firstCategory) {
          console.log('🔹 Setting initial category:', firstCategory);
        }
        return firstCategory;
      });
      setMessage(null);
    } catch (err) {
      console.error('❌ Error loading settings:', err);
      setMessage({
        type: 'error',
        text: err.response?.data?.error || err.message || 'Помилка завантаження налаштувань'
      });
    }
    setLoading(false);
  }, []);

  // Завантажити налаштування при монтуванні
  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSettingChange = (key, value, type) => {
    setChangedSettings(prev => ({
      ...prev,
      [key]: { value, type }
    }));
  };

  const saveSettings = async () => {
    if (Object.keys(changedSettings).length === 0) {
      setMessage({ type: 'info', text: 'Немає змін для збереження' });
      return;
    }

    try {
      setLoading(true);
      const settingsArray = Object.entries(changedSettings).map(([key, { value, type }]) => ({
        key,
        value,
        type
      }));

      const response = await apiClient.post('/api/admin/config/bulk-update', {
        settings: settingsArray
      });

      const updatedKeys = new Set((response.data.updated || []).map(item => item.key));
      const failedKeys = new Set((response.data.errors || []).map(item => item.key));

      if (response.data.success) {
        setMessage({
          type: 'success',
          text: `✓ Збережено ${response.data.updated.length} налаштувань`
        });
        setChangedSettings({});
        // Перезавантажити налаштування
        setTimeout(() => loadSettings(), 1000);
      } else {
        setMessage({
          type: 'warning',
          text: `Оновлено: ${response.data.updated.length}, Помилок: ${response.data.errors.length}`
        });
        setChangedSettings(prev => Object.fromEntries(
          Object.entries(prev).filter(([key]) => failedKeys.has(key))
        ));
        if (updatedKeys.size > 0) {
          setTimeout(() => loadSettings(), 600);
        }
      }
    } catch (err) {
      console.error('Error saving settings:', err);
      setMessage({
        type: 'error',
        text: err.response?.data?.error || 'Помилка збереження налаштувань'
      });
    }
    setLoading(false);
  };

  const resetChanges = () => {
    setChangedSettings({});
    setMessage(null);
  };

  const backupSettings = async () => {
    try {
      const response = await apiClient.get('/api/admin/config/backup/download');
      const source = response.data || {};
      const normalizedBackup = {
        ...source,
        currentValues: source.currentValues || source.values || {},
        settings: source.settings || source.schema || source.defaults || {},
        schema: source.schema || source.settings || source.defaults || {}
      };
      const dataStr = JSON.stringify(normalizedBackup, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `school-vouchers-settings-backup-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      
      setMessage({
        type: 'success',
        text: '✓ Бекап налаштувань скачаний'
      });
    } catch (err) {
      console.error('Error backing up settings:', err);
      setMessage({
        type: 'error',
        text: 'Помилка створення бекапу: ' + (err.response?.data?.error || err.message)
      });
    }
  };

  const resetToDefaults = async () => {
    const confirmed = window.confirm(
      '⚠️ Ви впевнені? Всі налаштування будуть скинуті на стандартні значення!'
    );

    if (!confirmed) return;

    try {
      setLoading(true);
      const response = await apiClient.post('/api/admin/config/reset-to-defaults', {});
      
      setMessage({
        type: 'success',
        text: response.data.message || '✓ Налаштування скинуті на стандартні'
      });
      setChangedSettings({});
      
      setTimeout(() => loadSettings(), 1500);
    } catch (err) {
      console.error('Error resetting settings:', err);
      setMessage({
        type: 'error',
        text: 'Помилка скидання налаштувань: ' + (err.response?.data?.error || err.message)
      });
    }
    setLoading(false);
  };

  const restoreFromBackup = async (file) => {
    try {
      const text = await file.text();
      const backupData = JSON.parse(text);
      const schema = backupData.settings || backupData.schema || backupData.defaults;
      const currentValues = backupData.currentValues || backupData.values;

      if (!schema && !currentValues) {
        throw new Error('Невірний формат бекапу');
      }

      setLoading(true);
      const payload = {};
      if (schema) payload.settings = schema;
      if (currentValues) payload.currentValues = currentValues;

      const response = await apiClient.post('/api/admin/config/restore', payload);

      setMessage({
        type: 'success',
        text: response.data.message || `✓ Відновлено ${response.data.restored} налаштувань`
      });
      setChangedSettings({});

      setTimeout(() => loadSettings(), 1500);
    } catch (err) {
      console.error('Error restoring settings:', err);
      setMessage({
        type: 'error',
        text: 'Помилка відновлення: ' + (err.response?.data?.error || err.message)
      });
    }
    setLoading(false);
  };

  const handleRestoreFile = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      const confirmed = window.confirm(
        '⚠️ Ви впевнені? Поточні налаштування будуть замінені на налаштування з файлу!'
      );
      if (confirmed) {
        restoreFromBackup(file);
      }
    }
    // Reset input
    e.target.value = '';
  };

  // Фільтрування налаштувань по категоріям
  const filteredSettings = searchTerm
    ? Object.keys(settings).reduce((acc, category) => {
        const categoryData = settings[category];
        if (!categoryData || !categoryData.settings) return acc;
        
        const normalizedSearch = String(searchTerm || '').toLowerCase();
        const filtered = categoryData.settings.filter(
          s => String(s.label || '').toLowerCase().includes(normalizedSearch) ||
               String(s.description || '').toLowerCase().includes(normalizedSearch)
        );
        if (filtered.length > 0) {
          acc[category] = { ...categoryData, settings: filtered };
        }
        return acc;
      }, {})
    : settings;

  // Ensure activeCategory exists in filtered results (update when settings/search change)
  useEffect(() => {
    try {
      const keys = Object.keys(filteredSettings || {});
      if (keys.length === 0) {
        setActiveCategory(null);
        return;
      }

      if (!activeCategory || !filteredSettings[activeCategory]) {
        setActiveCategory(keys[0]);
      }
    } catch (e) {
      // ignore
    }
  }, [searchTerm, settings, activeCategory, filteredSettings]);

  const renderSettingInput = (setting) => {
    const key = setting.key;
    const currentValue = changedSettings[key]?.value ?? setting.value;
    const settingType = changedSettings[key]?.type ?? setting.type;

    const commonProps = {
      onChange: (e) => handleSettingChange(key, e.target.value, settingType),
      className: 'setting-input'
    };

    switch (setting.type) {
      case 'boolean':
        return (
          <label className='setting-checkbox'>
            <input
              type='checkbox'
              checked={currentValue === true || currentValue === 'true'}
              onChange={(e) => handleSettingChange(key, e.target.checked ? 'true' : 'false', 'boolean')}
              disabled={setting.editable === false}
            />
          </label>
        );

      case 'select':
        return (
          <select
            value={currentValue}
            {...commonProps}
            disabled={setting.editable === false}
          >
            {setting.options?.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        );

      case 'textarea':
        return (
          <textarea
            value={currentValue || ''}
            {...commonProps}
            rows={4}
            disabled={setting.editable === false}
          />
        );

      case 'number':
        return (
          <input
            type='number'
            value={currentValue || 0}
            {...commonProps}
            disabled={setting.editable === false}
            min={setting.min}
            max={setting.max}
            step={setting.step || 1}
          />
        );

      case 'text':
      default:
        return (
          <input
            type='text'
            value={currentValue || ''}
            {...commonProps}
            disabled={setting.editable === false}
            placeholder={setting.default}
          />
        );
    }
  };

  if (loading && Object.keys(settings).length === 0) {
    return (
      <div className='admin-settings loading'>
        <p>⏳ Завантаження налаштувань системи...</p>
      </div>
    );
  }

  if (Object.keys(settings).length === 0 && !loading) {
    return (
      <div className='admin-settings'>
        <div className='message message-error'>
          ❌ Не вдалось завантажити налаштування. Спробуйте перезавантажити сторінку.
          <button onClick={() => window.location.reload()} className='message-close'>↻</button>
        </div>
      </div>
    );
  }

  return (
    <div className='admin-settings'>
      <div className='settings-wrapper'>
      <div className='settings-header'>
        <h2>🔧 Налаштування Системи</h2>
        <div className='settings-search'>
          <input
            type='text'
            placeholder='Пошук налаштування...'
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className='search-input'
          />
        </div>
      </div>

      {message && (
        <div className={`message message-${message.type}`}>
          {message.text}
          <button onClick={() => setMessage(null)} className='message-close'>✕</button>
        </div>
      )}

      <div className='settings-container'>
        <div className='settings-categories'>
          {Object.keys(filteredSettings).length === 0 ? (
            <p className='no-categories'>Немає налаштувань</p>
          ) : (
            Object.keys(filteredSettings).map(category => (
              <button
                key={category}
                className={`category-btn ${activeCategory === category ? 'active' : ''}`}
                onClick={() => setActiveCategory(category)}
              >
                {filteredSettings[category].category}
                <span className='setting-count'>
                  {filteredSettings[category].settings?.length || 0}
                </span>
              </button>
            ))
          )}
        </div>

        <div className='settings-content'>
          {activeCategory && filteredSettings[activeCategory]?.settings ? (
            <>
              <h3>{filteredSettings[activeCategory].category}</h3>
              
              <div className='settings-list'>
                {filteredSettings[activeCategory].settings.length > 0 ? (
                  filteredSettings[activeCategory].settings.map(setting => {
                    const isChanged = changedSettings[setting.key] !== undefined;
                    
                    return (
                      <div key={setting.key} className={`setting-item ${isChanged ? 'changed' : ''}`}>
                        <div className='setting-label'>
                          <label>
                            {setting.label}
                            {(setting.help || setting.description) && (
                              <span
                                className='help-icon'
                                data-tooltip={setting.help || setting.description}
                                tabIndex={0}
                                aria-label={setting.help || setting.description}
                              >
                                ?
                              </span>
                            )}
                          </label>
                          {isChanged && <span className='changed-indicator'>●</span>}
                        </div>
                        
                        {setting.description && (
                          <p className='setting-description'>{setting.description}</p>
                        )}

                        <div className='setting-value'>
                          {renderSettingInput(setting)}
                          
                          {setting.min !== undefined && setting.max !== undefined && (
                            <span className='setting-range'>
                              ({setting.min} - {setting.max})
                            </span>
                          )}
                        </div>

                        {setting.editable === false && (
                          <p className='setting-hint'>
                            ℹ️  Це налаштування змінюється тільки через .env файл (потребує перезавантаження сервера)
                          </p>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <p className='no-settings'>Немає налаштувань у цій категорії</p>
                )}
              </div>
            </>
          ) : (
            <div className='settings-content-empty'>
              <p>Виберіть категорію зліва</p>
            </div>
          )}
        </div>
      </div>

      <div className='settings-actions'>
        <div className='changes-info'>
          {Object.keys(changedSettings).length > 0 && (
            <p className='changes-count'>
              ⚡ Змінено: <strong>{Object.keys(changedSettings).length}</strong> налаштувань
            </p>
          )}
        </div>

        <div className='action-buttons'>
          {Object.keys(changedSettings).length > 0 && (
            <>
              <button
                className='btn btn-primary'
                onClick={saveSettings}
                disabled={loading}
              >
                💾 Зберегти
              </button>
              <button
                className='btn btn-secondary'
                onClick={resetChanges}
              >
                ↻ Скасувати
              </button>
            </>
          )}
          
          <button
            className='btn btn-info'
            onClick={loadSettings}
            disabled={loading}
          >
            🔄 Перезавантажити
          </button>
        </div>

        <div className='backup-buttons'>
          <button
            className='btn btn-warning'
            onClick={backupSettings}
            title='Скачати бекап поточних налаштувань'
          >
            💾 Бекап
          </button>

          <label className='btn btn-success'>
            📥 Відновити
            <input
              type='file'
              accept='.json'
              onChange={handleRestoreFile}
              style={{ display: 'none' }}
            />
          </label>

          <button
            className='btn btn-danger'
            onClick={resetToDefaults}
            title='⚠️ Скинути всі налаштування на стандартні'
          >
            🔄 Дефолт
          </button>
        </div>
      </div>

      <div className='settings-footer'>
        <p className='footer-note'>
          ℹ️  Налаштування зберігаються в базі даних. Деякі налаштування можуть потребувати перезавантаження сервера.
        </p>
      </div>
      </div>
    </div>
  );
}

export default AdminSettings;
