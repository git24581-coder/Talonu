import React, { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import apiClient from '../api/client.js';

const T = {
  title: '\uD83D\uDD0D \u0421\u043a\u0430\u043d\u0443\u0432\u0430\u043d\u043d\u044f \u0442\u0430\u043b\u043e\u043d\u0456\u0432',
  qrNotFound: 'QR \u043a\u043e\u0434 \u043d\u0435 \u0437\u043d\u0430\u0439\u0434\u0435\u043d\u043e \u0430\u0431\u043e \u043f\u043e\u043c\u0438\u043b\u043a\u0430 \u043f\u0440\u0438 \u043e\u0431\u0440\u043e\u0431\u0446\u0456',
  cameraAccessError: '\u041d\u0435 \u0432\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0442\u0440\u0438\u043c\u0430\u0442\u0438 \u0434\u043e\u0441\u0442\u0443\u043f \u0434\u043e \u043a\u0430\u043c\u0435\u0440\u0438',
  serverCheckFallback: '\u041d\u0435 \u0432\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u0435\u0440\u0435\u0432\u0456\u0440\u0438\u0442\u0438 \u043a\u043e\u0434 \u043d\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0456 - \u043f\u043e\u043a\u0430\u0437\u0430\u043d\u043e \u0441\u0438\u0440\u0438\u0439 \u0440\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442',
  markedSuccess: '\u0422\u0430\u043b\u043e\u043d \u043f\u043e\u0437\u043d\u0430\u0447\u0435\u043d\u043e \u044f\u043a \u0432\u0438\u043a\u043e\u0440\u0438\u0441\u0442\u0430\u043d\u0438\u0439',
  markError: '\u041f\u043e\u043c\u0438\u043b\u043a\u0430 \u043f\u0440\u0438 \u043f\u043e\u0437\u043d\u0430\u0447\u0435\u043d\u043d\u0456 \u0442\u0430\u043b\u043e\u043d\u0443',
  inputPlaceholder: '\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 \u0441\u043a\u0430\u043d\u0443\u0432\u0430\u043d\u043d\u044f \u0430\u0431\u043e \u0440\u0443\u0447\u043d\u0435 \u0432\u0432\u0435\u0434\u0435\u043d\u043d\u044f',
  unknownStudent: '\u041d\u0435\u0432\u0456\u0434\u043e\u043c\u0438\u0439 \u0443\u0447\u0435\u043d\u044c',
  noClass: '(\u0411\u0435\u0437 \u043a\u043b\u0430\u0441\u0443)',
  statusUsed: '\u0412\u0418\u041a\u041e\u0420\u0418\u0421\u0422\u0410\u041d\u041e',
  statusExhausted: '\u0412\u0418\u0427\u0415\u0420\u041f\u0410\u041d\u041e',
  statusExpired: '\u041f\u0420\u041e\u0421\u0422\u0420\u041e\u0427\u0415\u041d\u041e',
  statusActive: '\u0414\u0406\u0419\u0421\u041d\u0418\u0419',
  processing: '\u041e\u0431\u0440\u043e\u0431\u043a\u0430...',
  markUsed: '\u041f\u043e\u0437\u043d\u0430\u0447\u0438\u0442\u0438 \u044f\u043a \u0432\u0438\u043a\u043e\u0440\u0438\u0441\u0442\u0430\u043d\u0438\u0439'
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
