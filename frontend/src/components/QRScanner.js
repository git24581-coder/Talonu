import React, { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import apiClient from '../api/client.js';

const T = {
  title: '🔍 Сканування талонів',
  qrNotFound: 'QR-код не знайдено або сталася помилка під час обробки',
  cameraAccessError: 'Не вдалося отримати доступ до камери',
  serverCheckFallback: 'Не вдалося перевірити код на сервері - показано сирий результат',
  markedSuccess: 'Талон позначено як використаний',
  markError: 'Помилка під час позначення талона',
  inputPlaceholder: 'Результат сканування або ручне введення коду',
  unknownStudent: 'Невідомий учень',
  noClass: '(Без класу)',
  statusUsed: 'ВИКОРИСТАНО',
  statusExhausted: 'ВИКОРИСТАНО',
  statusExpired: 'ПРОСТРОЧЕНО',
  statusActive: 'ДІЙСНИЙ',
  processing: 'Обробка...',
  markUsed: 'Позначити як використаний'
};

function QRScanner({ onScan, isVisible }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const inputRef = useRef(null);
  const rafRef = useRef(null);
  const streamRef = useRef(null);
  const onScanRef = useRef(onScan);

  const [error, setError] = useState('');
  const [voucher, setVoucher] = useState(null);
  const [usingVoucher, setUsingVoucher] = useState(false);

  useEffect(() => {
    onScanRef.current = onScan;
  }, [onScan]);

  useEffect(() => {
    const stopCamera = () => {
      try {
        if (rafRef.current) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = null;
        }

        const videoElement = videoRef.current;
        if (videoElement) {
          try {
            videoElement.onloadedmetadata = null;
            videoElement.pause();
            if (videoElement.srcObject && typeof videoElement.srcObject.getTracks === 'function') {
              videoElement.srcObject.getTracks().forEach((track) => track.stop());
            }
            videoElement.srcObject = null;
          } catch (pauseErr) {
            console.warn('Error pausing video:', pauseErr);
          }
        }

        if (streamRef.current) {
          try {
            streamRef.current.getTracks().forEach((track) => track.stop());
          } catch (streamErr) {
            console.warn('Error stopping stream tracks:', streamErr);
          }
          streamRef.current = null;
        }
      } catch (cleanupErr) {
        console.warn('Error in QRScanner cleanup:', cleanupErr);
      }
    };

    if (!isVisible) {
      stopCamera();
      return undefined;
    }

    let isCancelled = false;
    const videoElement = videoRef.current;

    const processQRCode = async (value) => {
      const trimmed = value.trim();
      if (!trimmed || trimmed.length <= 5) return;

      try {
        const response = await apiClient.get(`/api/vouchers/check/${encodeURIComponent(trimmed)}`);
        const voucherData = response.data;
        setVoucher(voucherData);
        if (inputRef.current) inputRef.current.value = trimmed;
        if (onScanRef.current) onScanRef.current(voucherData);
        setError('');
      } catch (scanError) {
        console.error('Error checking voucher:', scanError);
        setError(scanError.response?.data?.error || T.qrNotFound);
      }
    };

    const startScanning = () => {
      const canvas = canvasRef.current;
      const video = videoRef.current;
      if (!canvas || !video) return;

      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      const processSize = 400;
      canvas.width = processSize;
      canvas.height = processSize;

      let frameCount = 0;
      const scanInterval = 2;
      const lastResultRef = { value: null, ts: 0 };

      const scan = () => {
        if (!video.paused && !video.ended) {
          frameCount += 1;

          if (frameCount % scanInterval === 0) {
            const vw = video.videoWidth || video.clientWidth;
            const vh = video.videoHeight || video.clientHeight;
            const side = Math.min(vw, vh);
            const sx = Math.max(0, Math.floor((vw - side) / 2));
            const sy = Math.max(0, Math.floor((vh - side) / 2));

            try {
              ctx.drawImage(video, sx, sy, side, side, 0, 0, processSize, processSize);
            } catch (drawErr) {
              rafRef.current = requestAnimationFrame(scan);
              return;
            }

            const imageData = ctx.getImageData(0, 0, processSize, processSize);
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            if (code && code.data) {
              const now = Date.now();
              if (!(code.data === lastResultRef.value && now - lastResultRef.ts < 3000)) {
                lastResultRef.value = code.data;
                lastResultRef.ts = now;

                try {
                  if (inputRef.current) inputRef.current.value = code.data;
                } catch (setInputErr) {
                  console.warn('Cannot set input value', setInputErr);
                }

                processQRCode(code.data).catch((processErr) => {
                  console.error('processQRCode failed:', processErr);
                  setError(T.serverCheckFallback);
                  try {
                    if (onScanRef.current) onScanRef.current({ raw: code.data });
                  } catch (fallbackErr) {
                    console.error('onScan fallback failed', fallbackErr);
                  }
                });
              }
            }
          }
        }

        rafRef.current = requestAnimationFrame(scan);
      };

      scan();
    };

    const initCamera = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' }
        });
        if (isCancelled || !isVisible) {
          stream.getTracks().forEach((track) => track.stop());
          return;
        }
        streamRef.current = stream;

        if (videoElement) {
          videoElement.srcObject = stream;
          videoElement.onloadedmetadata = startScanning;
          setError('');
        }
      } catch (cameraErr) {
        setError(T.cameraAccessError);
      }
    };

    initCamera();

    return () => {
      isCancelled = true;
      stopCamera();
    };
  }, [isVisible]);

  const processQRCodeManual = async (value) => {
    const trimmed = value.trim();
    if (!trimmed || trimmed.length <= 5) return;

    try {
      const response = await apiClient.get(`/api/vouchers/check/${encodeURIComponent(trimmed)}`);
      const voucherData = response.data;
      setVoucher(voucherData);
      if (onScanRef.current) onScanRef.current(voucherData);
      if (inputRef.current) inputRef.current.value = trimmed;
      setError('');
    } catch (manualErr) {
      console.error('Error checking voucher:', manualErr);
      setError(manualErr.response?.data?.error || T.qrNotFound);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      processQRCodeManual(e.target.value);
    }
  };

  const handleInputChange = (e) => {
    const value = e.target.value.trim();
    if (value && value.length > 10) {
      processQRCodeManual(value);
    }
  };

  const markAsUsed = async () => {
    if (!voucher || !voucher.qr_code) return;

    setUsingVoucher(true);
    try {
      const body = {
        qrCode: voucher.qr_code,
        studentId: voucher.user_id || null,
        studentName: voucher.student_name || null
      };
      const resp = await apiClient.post('/api/vouchers/use', body);
      const updated = resp.data.updatedVoucher || resp.data.voucher || null;
      if (updated) setVoucher((prev) => ({ ...prev, ...updated }));
      setError(resp.data.message || T.markedSuccess);
    } catch (useErr) {
      console.error('Error marking used:', useErr);
      setError(useErr.response?.data?.error || T.markError);
    }
    setUsingVoucher(false);
  };

  const isVoucherAlreadyUsed = voucher
    ? Boolean(
        voucher.usedToday
        || voucher.isExhausted
        || voucher.isExpired
        || voucher.isUsed
        || (Number(voucher.current_uses || 0) >= Number(voucher.max_uses || 1))
      )
    : false;

  const statusText = voucher
    ? (voucher.usedToday
        ? T.statusUsed
        : voucher.isExhausted || voucher.isUsed || Number(voucher.current_uses || 0) >= Number(voucher.max_uses || 1)
          ? T.statusExhausted
          : voucher.isExpired
            ? T.statusExpired
            : T.statusActive)
    : '';

  const statusColor = voucher && isVoucherAlreadyUsed ? '#EF4444' : '#10B981';

  if (!isVisible) return null;

  return (
    <div>
      <h2 style={{ marginTop: 0, color: '#111827', marginBottom: '20px' }}>{T.title}</h2>
      {error && <div className="alert alert-error">{error}</div>}

      <div style={{ position: 'relative', width: '100%', maxWidth: '500px', margin: '0 auto' }}>
        <canvas ref={canvasRef} style={{ display: 'none' }} />

        <div
          style={{
            position: 'relative',
            width: '100%',
            paddingBottom: '100%',
            backgroundColor: '#000',
            borderRadius: '12px',
            overflow: 'hidden',
            marginBottom: '16px'
          }}
        >
          <video
            ref={videoRef}
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: '100%',
              height: '100%',
              objectFit: 'cover'
            }}
            autoPlay
            playsInline
            muted
          />
        </div>

        <input
          ref={inputRef}
          type="text"
          placeholder={T.inputPlaceholder}
          onKeyPress={handleKeyPress}
          onChange={handleInputChange}
          style={{
            padding: '12px',
            width: '100%',
            borderRadius: '8px',
            border: '1px solid #D1D5DB',
            fontSize: '14px',
            fontFamily: 'inherit',
            color: '#111827',
            backgroundColor: '#FFFFFF',
            boxSizing: 'border-box'
          }}
        />

        {voucher && (
          <div
            style={{
              marginTop: '12px',
              padding: '12px',
              borderRadius: '8px',
              backgroundColor: '#FFFFFF',
              boxShadow: '0 2px 8px rgba(0,0,0,0.06)'
            }}
          >
            <div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: '#111827' }}>
                {voucher.student_name || T.unknownStudent}
              </div>
              <div style={{ fontSize: '14px', color: '#6B7280', marginTop: '6px' }}>
                {voucher.class_name ? voucher.class_name : T.noClass}
              </div>
              <div style={{ fontSize: '12px', color: '#9CA3AF', marginTop: '6px' }}>
                {voucher.user_id ? `ID: ${voucher.user_id}` : ''}
              </div>
              <div style={{ marginTop: '8px', fontSize: '14px', fontWeight: 700, color: statusColor }}>
                {statusText}
              </div>
              {voucher.expiresMessage && (
                <div style={{ fontSize: '12px', color: '#6B7280', marginTop: '4px' }}>
                  {voucher.expiresMessage}
                </div>
              )}
            </div>

            {!isVoucherAlreadyUsed && (
              <div style={{ marginTop: '10px' }}>
                <button
                  className="btn-primary btn-block qr-mark-used-btn"
                  onClick={markAsUsed}
                  disabled={usingVoucher}
                >
                  {usingVoucher ? T.processing : T.markUsed}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default QRScanner;
