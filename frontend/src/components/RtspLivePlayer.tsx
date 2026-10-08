import { useEffect, useRef, useState } from 'react';

export function liveStreamUrl(pageId: number): string {
  return `/api/web-pages/${pageId}/live`;
}

export function deviceRtspLiveUrl(deviceUuid: string, port: number): string {
  return `/api/devices/${deviceUuid}/rtsp/${port}/live`;
}

type Phase = 'idle' | 'connecting' | 'streaming' | 'failed';

/** On-demand MJPEG viewer (starts only when the user clicks Watch, unless autoStart). */
export function RtspLivePlayer({
  src,
  label = 'RTSP live',
  posterUrl,
  autoStart = false,
}: {
  src: string;
  label?: string;
  posterUrl?: string | null;
  autoStart?: boolean;
}) {
  const [phase, setPhase] = useState<Phase>(autoStart ? 'connecting' : 'idle');
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const imgRef = useRef<HTMLImageElement | null>(null);

  useEffect(() => {
    setPhase(autoStart ? 'connecting' : 'idle');
    setError(null);
  }, [src, autoStart]);

  // If the img never paints real pixels (black/empty stream), surface an error.
  useEffect(() => {
    if (phase !== 'connecting' && phase !== 'streaming') return;
    const t = window.setTimeout(() => {
      const img = imgRef.current;
      if (!img || img.naturalWidth < 2 || img.naturalHeight < 2) {
        setError('No video frames received. This port may not be a real RTSP camera (wrong path, auth, or nmap mislabel).');
        setPhase('failed');
      }
    }, 8000);
    return () => window.clearTimeout(t);
  }, [phase, nonce, src]);

  const feedSrc = `${src}${src.includes('?') ? '&' : '?'}_=${nonce}`;
  const playing = phase === 'connecting' || phase === 'streaming';

  return (
    <div className="rtsp-player">
      <div className="rtsp-stage">
        {(phase === 'connecting' || phase === 'streaming') ? (
          <img
            ref={imgRef}
            className="rtsp-feed"
            src={feedSrc}
            alt={label}
            onLoad={() => {
              const img = imgRef.current;
              if (img && img.naturalWidth > 1 && img.naturalHeight > 1) {
                setPhase('streaming');
                setError(null);
              }
            }}
            onError={async () => {
              let msg = 'Live stream failed (ffmpeg, path, or auth).';
              try {
                const r = await fetch(feedSrc, { credentials: 'same-origin' });
                if (!r.ok) {
                  const body = await r.text();
                  msg = body.trim().slice(0, 200) || `Live stream failed (HTTP ${r.status})`;
                }
              } catch {
                /* keep default */
              }
              setError(msg);
              setPhase('failed');
            }}
          />
        ) : posterUrl && phase === 'idle' ? (
          <img className="rtsp-feed rtsp-poster" src={posterUrl} alt="" />
        ) : (
          <div className="rtsp-ph">
            <span>
              {phase === 'failed'
                ? (error ?? 'Live stream failed')
                : 'Live stream paused'}
            </span>
          </div>
        )}
        {phase === 'connecting' && (
          <div className="rtsp-overlay"><span className="spinner" /> Connecting…</div>
        )}
      </div>
      <div className="rtsp-controls row wrap">
        {!playing ? (
          <button
            className="btn primary sm"
            onClick={() => { setError(null); setPhase('connecting'); setNonce((n) => n + 1); }}
          >
            Watch live
          </button>
        ) : (
          <button className="btn sm" onClick={() => { setPhase('idle'); setError(null); }}>Stop</button>
        )}
        {phase === 'failed' && (
          <button
            className="btn sm"
            onClick={() => { setError(null); setPhase('connecting'); setNonce((n) => n + 1); }}
          >
            Retry
          </button>
        )}
        <span className="muted small">
          {phase === 'streaming'
            ? 'Streaming via server MJPEG proxy'
            : phase === 'connecting'
              ? 'Opening RTSP…'
              : phase === 'failed'
                ? 'Stream unavailable'
                : 'Click Watch live to start'}
        </span>
      </div>
    </div>
  );
}
