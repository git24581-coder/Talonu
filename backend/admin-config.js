// Admin Configuration Management Module
// Handles system settings, configuration storage, and runtime configs

const { v4: uuidv4 } = require('uuid');

const runtimeConfig = {};

const DEFAULT_SETTINGS = {
  System: {
    icon: 'SYS',
    category: 'Система',
    settings: [
      {
        key: 'app_name',
        label: 'Назва застосунку',
        default: 'Шкільні талони',
        type: 'string',
        category: 'System',
        description: 'Назва системи, яка відображається в інтерфейсі'
      },
      {
        key: 'app_version',
        label: 'Версія',
        default: '1.0.0',
        type: 'string',
        category: 'System',
        description: 'Поточна версія застосунку',
        editable: false
      },
      {
        key: 'maintenance_mode',
        label: 'Режим обслуговування',
        default: false,
        type: 'boolean',
        category: 'System',
        description: 'Тимчасово обмежує доступ до системи'
      }
    ]
  },
  Vouchers: {
    icon: 'VOU',
    category: 'Талони',
    settings: [
      {
        key: 'voucher_expiry_hours',
        label: 'Термін дії талону (години)',
        default: 9,
        type: 'number',
        category: 'Vouchers',
        description: 'Скільки годин талон залишається дійсним',
        min: 1,
        max: 72
      },
      {
        key: 'voucher_auto_generate',
        label: 'Автогенерація талонів',
        default: true,
        type: 'boolean',
        category: 'Vouchers',
        description: 'Автоматично створювати талони для присутніх учнів'
      },
      {
        key: 'voucher_daily_limit',
        label: 'Добовий ліміт талонів',
        default: 1000,
        type: 'number',
        category: 'Vouchers',
        description: 'Максимальна кількість талонів, які можна видати за день',
        min: 1,
        max: 100000
      }
    ]
  },
  Security: {
    icon: 'SEC',
    category: 'Безпека',
    settings: [
      {
        key: 'jwt_expiry_hours',
        label: 'Термін дії JWT (години)',
        default: 24,
        type: 'number',
        category: 'Security',
        description: 'Час до автоматичного завершення сесії',
        min: 1,
        max: 168
      },
      {
        key: 'max_login_attempts',
        label: 'Максимум спроб входу',
        default: 5,
        type: 'number',
        category: 'Security',
        description: 'Кількість невдалих спроб до тимчасового блокування',
        min: 1,
        max: 20
      },
      {
        key: 'session_timeout_minutes',
        label: 'Таймаут сесії (хвилини)',
        default: 60,
        type: 'number',
        category: 'Security',
        description: 'Час бездіяльності до автоматичного виходу',
        min: 5,
        max: 1440
      }
    ]
  },
  Database: {
    icon: 'DB',
    category: 'База даних',
    settings: [
      {
        key: 'db_backup_daily',
        label: 'Щоденний бекап',
        default: true,
        type: 'boolean',
        category: 'Database',
        description: 'Дозволяє автоматичне щоденне резервне копіювання'
      },
      {
        key: 'db_cache_ttl_seconds',
        label: 'TTL кешу БД (секунди)',
        default: 300,
        type: 'number',
        category: 'Database',
        description: 'Як довго тримати дані в кеші',
        min: 0,
        max: 86400
      }
    ]
  },
  Notifications: {
    icon: 'NOT',
    category: 'Сповіщення',
    settings: [
      {
        key: 'notify_voucher_expiry',
        label: 'Сповіщення про завершення талонів',
        default: true,
        type: 'boolean',
        category: 'Notifications',
        description: 'Сповіщати адміністраторів про завершення терміну дії талонів'
      },
      {
        key: 'notify_low_stock',
        label: 'Сповіщення про малий залишок',
        default: true,
        type: 'boolean',
        category: 'Notifications',
        description: 'Сповіщати, коли доступних талонів стає мало'
      }
    ]
  }
};

/**
 * Initialize admin configuration
 */
function initAdminConfig(db, callback) {
  try {
    db.run(
      `
      CREATE TABLE IF NOT EXISTS config (
        id TEXT PRIMARY KEY,
        key TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL,
        type TEXT DEFAULT 'string',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_by TEXT,
        description TEXT
      )
      `,
      (err) => {
        if (err) {
          console.error('Error creating config table:', err);
          if (callback) callback(err);
          return;
        }

        db.all('SELECT key, value, type FROM config', (loadErr, rows) => {
          if (loadErr) {
            console.error('Error loading config:', loadErr);
            if (callback) callback(loadErr);
            return;
          }

          if (rows && Array.isArray(rows)) {
            rows.forEach((config) => {
              runtimeConfig[config.key] = parseConfigValue(config.value, config.type);
            });
          }

          console.log(`Admin config initialized (${Object.keys(runtimeConfig).length} settings loaded)`);
          if (callback) callback(null);
        });
      }
    );
  } catch (err) {
    console.error('Error initializing admin config:', err);
    if (callback) callback(err);
  }
}

/**
 * Parse config value based on type
 */
function parseConfigValue(value, type) {
  if (value === null || value === undefined) {
    return undefined;
  }

  if (type === 'boolean') {
    if (typeof value === 'boolean') return value;
    return value === 'true' || value === '1' || value === true || value === 1;
  }

  if (type === 'number') {
    const num = typeof value === 'number' ? value : Number(value);
    return Number.isFinite(num) ? num : 0;
  }

  if (type === 'json') {
    if (typeof value === 'object') return value;
    try {
      return JSON.parse(value);
    } catch (e) {
      console.warn(`Failed to parse JSON for key: ${value}`, e);
      return value;
    }
  }

  return value;
}

/**
 * Save config value to database and runtime
 */
function saveConfigValue(db, key, value, type, userId, callback) {
  if (typeof userId === 'function') {
    callback = userId;
    userId = null;
  }

  const executeSave = (resolve, reject) => {
    try {
      const setting = getSettingDefinition(key);
      if (!setting) {
        const err = new Error(`Unknown config key: ${key}`);
        console.error(err);
        reject(err);
        return;
      }

      const configType = type || setting.type;
      const parsedValue = parseConfigValue(value, configType);

      if (configType === 'number' && !Number.isFinite(parsedValue)) {
        const err = new Error(`Invalid number value for ${key}: ${value}`);
        console.error(err);
        reject(err);
        return;
      }

      const stringValue = configType === 'json' || typeof parsedValue === 'object'
        ? JSON.stringify(parsedValue)
        : String(parsedValue);

      db.get('SELECT id FROM config WHERE key = ?', [key], (selectErr, existing) => {
        if (selectErr) {
          console.error(`Error checking config key ${key}:`, selectErr);
          reject(selectErr);
          return;
        }

        if (existing && existing.id) {
          db.run(
            `UPDATE config
             SET value = ?, type = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
             WHERE key = ?`,
            [stringValue, configType, userId || null, key],
            (updateErr) => {
              if (updateErr) {
                console.error(`Error updating config value ${key}:`, updateErr);
                reject(updateErr);
                return;
              }

              runtimeConfig[key] = parsedValue;
              resolve({ key, value: parsedValue, type: configType });
            }
          );
          return;
        }

        const id = uuidv4();
        db.run(
          `INSERT INTO config (id, key, value, type, updated_by, updated_at)
           VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
          [id, key, stringValue, configType, userId || null],
          (insertErr) => {
            if (insertErr) {
              console.error(`Error inserting config value ${key}:`, insertErr);
              reject(insertErr);
              return;
            }

            runtimeConfig[key] = parsedValue;
            resolve({ key, value: parsedValue, type: configType });
          }
        );
      });
    } catch (err) {
      console.error(`Error in saveConfigValue ${key}:`, err);
      reject(err);
    }
  };

  if (typeof callback === 'function') {
    executeSave(
      () => callback(null),
      (err) => callback(err)
    );
    return;
  }

  return new Promise(executeSave);
}

/**
 * Get runtime config value
 */
function getRuntimeConfigValue(key) {
  return runtimeConfig[key];
}

/**
 * Get all runtime configs
 */
function getAllRuntimeConfig() {
  return { ...runtimeConfig };
}

/**
 * Get all configurable settings (with defaults)
 */
function getAllConfigurableSettings() {
  const settingsWithValues = JSON.parse(JSON.stringify(DEFAULT_SETTINGS));

  Object.keys(settingsWithValues).forEach((categoryName) => {
    const category = settingsWithValues[categoryName];
    if (!category || !Array.isArray(category.settings)) {
      return;
    }

    category.settings = category.settings.map((setting) => {
      const hasRuntimeValue = Object.prototype.hasOwnProperty.call(runtimeConfig, setting.key);
      return {
        ...setting,
        value: hasRuntimeValue ? runtimeConfig[setting.key] : setting.default
      };
    });
  });

  return settingsWithValues;
}

/**
 * Get specific setting definition
 */
function getSettingDefinition(key) {
  for (const category in DEFAULT_SETTINGS) {
    const categorySettings = DEFAULT_SETTINGS[category]?.settings;
    if (Array.isArray(categorySettings)) {
      const setting = categorySettings.find((s) => s.key === key);
      if (setting) return setting;
    }
  }
  return null;
}

module.exports = {
  initAdminConfig,
  saveConfigValue,
  getRuntimeConfigValue,
  getAllRuntimeConfig,
  getAllConfigurableSettings,
  getSettingDefinition,
  parseConfigValue
};
