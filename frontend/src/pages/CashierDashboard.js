import React from 'react';
import QRScanner from '../components/QRScanner.js';
import './CashierDashboard.css';
import './SharedRoleTabs.css';

function CashierDashboard() {
  return (
    <div className="cashier-container">
      <div className="tab-content shared-tab-content">
        <QRScanner
          isVisible={true}
          onScan={(data) => {
            console.log('Voucher scanned:', data);
          }}
        />
      </div>
    </div>
  );
}

export default CashierDashboard;
