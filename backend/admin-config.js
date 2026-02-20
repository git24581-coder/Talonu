// Admin Configuration Management Module
// Handles system settings, configuration storage, and runtime configs

const { v4: uuidv4 } = require('uuid');

const runtimeConfig = {};

const DEFAULT_SETTINGS = {
  'System': {
    icon: 'SYS',
    settings: [
      {
        key: 'app_name',
        label: 'Назва додатку',
        default: 'Шкільні талони - Система управління талонами',
        type: 'string',
        category: 'System',
        description: 'Назва системи'
      },
      {
        key: 'app_version',
        label: 'Версія',
        default: '1.0.0',
        type: 'string',
        category: 'System',
        description: 'Версія системи'
      },
      {
        key: 'maintenance_mode',
        label: 'Режим обслуговування',
        default: false,
        type: 'boolean',
        category: 'System',
        description: 'Увімкнути режим обслуговування'
      }
    ]
  },
  'Vouchers': {
    icon: 'VOU',
    settings: [
      {
        key: 'voucher_expiry_hours',
        label: 'Час дії талону (часів)',
        default: 9,
        type: 'number',
        category: 'Vouchers',
        description: 'Кількість годин для дії талону'
      },
      {
        key: 'voucher_auto_generate',
        label: 'Автоматичне генерування',
        default: true,
        type: 'boolean',
        category: 'Vouchers',
        description: 'Автоматично генерувати талони для нових учнів'
      },
      {
        key: 'voucher_daily_limit',
        label: 'Щоденний ліміт',
        default: 1000,
        type: 'number',
        category: 'Vouchers',
        description: 'Максимум талонів на день'
      }
    ]
  },
  'Security': {
    icon: 'SEC',
    settings: [
      {
        key: 'jwt_expiry_hours',
        label: 'Час дії JWT токена (годин)',
        default: 24,
        type: 'number',
        category: 'Security',
        description: 'Час до закінчення JWT токена'
      },
      {
        key: 'max_login_attempts',
        label: 'Максимум спроб входу',
        default: 5,
        type: 'number',
        category: 'Security',
        description: 'Максимум невдалих спроб входу перед блокуванням'
      },
      {
        key: 'session_timeout_minutes',
        label: 'Тайм-аут сесії (хвилин)',
        default: 60,
        type: 'number',
        category: 'Security',
        description: 'Час неактивності перед логаутом'
      }
    ]
  },
  'Database': {
    icon: 'DB',
    settings: [
      {
        key: 'db_backup_daily',
        label: 'Щоденний бекап',
        default: true,
        type: 'boolean',
        category: 'Database',
        description: 'Автоматичний дефрагментуючи бекап БД'
      },
      {
        key: 'db_cache_ttl_seconds',
        label: 'TTL кешу БД (сек)',
        default: 300,
        type: 'number',
        category: 'Database',
        description: 'Час життя кешу запитів'
      }
    ]
  },
  'Notifications': {
    icon: 'NOT',
    settings: [
      {
        key: 'notify_voucher_expiry',
        label: 'Сповіщення про закінчення',
        default: true,
        type: 'boolean',
        category: 'Notifications',
        description: 'Сповіщувати про закінчення талонів'
      },
      {
        key: 'notify_low_stock',
        label: 'Сповіщення про мало талонів',
        default: true,
        type: 'boolean',
        category: 'Notifications',
        description: 'Сповіщувати коли малу кількість талонів'
      }
    ]
  }
};

/**
 * Initialize admin configuration
 */
function initAdminConfig(db, callback) {
  try {
    // Create config table if it doesn't exist
    db.run(`
      CREATE TABLE IF NOT EXISTS config (
        id TEXT PRIMARY KEY,
        key TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL,
        type TEXT DEFAULT 'string',
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_by TEXT,
        description TEXT
      )
    `, (err) => {
      if (err) {
        console.error('Error creating config table:', err);
        if (callback) callback(err);
        return;
      }

      // Load existing configs into runtime config
      db.all('SELECT key, value, type FROM config', (err, rows) => {
        if (err) {
          console.error('Error loading config:', err);
          if (callback) callback(err);
          return;
        }

        if (rows && Array.isArray(rows)) {
          rows.forEach(config => {
            const parsedValue = parseConfigValue(config.value, config.type);
            runtimeConfig[config.key] = parsedValue;
          });
        }

        console.log(`✓ Admin config initialized (${Object.keys(runtimeConfig).length} settings loaded)`);
        if (callback) callback(null);
      });
    });
  } catch (err) {
    console.error('Error initializing admin config:', err);
    if (callback) callback(err);
  }
}

/**
 * Parse config value based on type
 */
function parseConfigValue(value, type) {
  // Handle null/undefined
  if (value === null || value === undefined) {
    return undefined;
  }

  if (type === 'boolean') {
    if (typeof value === 'boolean') return value;
    return value === 'true' || value === '1' || value === true;
  }
  if (type === 'number') {
    const num = typeof value === 'number' ? value : parseInt(value, 10);
    return isNaN(num) ? 0 : num;
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
      // Validate key exists in settings
      const setting = getSettingDefinition(key);
      if (!setting) {
        const err = new Error(`Unknown config key: ${key}`);
        console.error(err);
        reject(err);
        return;
      }

      // Use provided type or default to setting type
      const configType = type || setting.type;

      // Parse and validate value
      const parsedValue = parseConfigValue(value, configType);
      let stringValue;

      // Convert to string for storage
      if (configType === 'json' || typeof parsedValue === 'object') {
        stringValue = JSON.stringify(parsedValue);
      } else {
        stringValue = String(parsedValue);
      }

      // Validate value constraints
      if (configType === 'number' && Number.isNaN(parsedValue)) {
        const err = new Error(`Invalid number value for ${key}: ${value}`);
        console.error(err);
        reject(err);
        return;
      }

      const id = uuidv4();

      db.run(`
        INSERT OR REPLACE INTO config (id, key, value, type, updated_by, updated_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `, [id, key, stringValue, configType, userId || null], (err) => {
        if (err) {
          console.error(`Error saving config value ${key}:`, err);
          reject(err);
          return;
        }

        // Update runtime config with parsed value
        runtimeConfig[key] = parsedValue;

        console.log(`Config saved: ${key} = ${stringValue} (type: ${configType})`);
        resolve({ key, value: parsedValue, type: configType });
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
    if (DEFAULT_SETTINGS[category].settings && Array.isArray(DEFAULT_SETTINGS[category].settings)) {
      const setting = DEFAULT_SETTINGS[category].settings.find(s => s.key === key);
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
