import { useEffect, useRef, type ReactNode } from 'react';

/** Disclosure popover (same <details> pattern as the system menu): closes on outside click or Escape. */
export function Popover({ label, title, className, buttonClassName = 'btn sm', panelClassName, children }: {
  label: ReactNode;
  title?: string;
  className?: string;
  buttonClassName?: string;
  panelClassName?: string;
  children: (close: () => void) => ReactNode;
}) {
  const ref = useRef<HTMLDetailsElement>(null);
  const close = () => { if (ref.current) ref.current.open = false; };

  useEffect(() => {
    const onEvent = (e: Event) => {
      const el = ref.current;
      if (!el?.open) return;
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !el.contains(e.target as Node)) el.open = false;
    };
    document.addEventListener('mousedown', onEvent);
    document.addEventListener('keydown', onEvent);
    return () => {
      document.removeEventListener('mousedown', onEvent);
      document.removeEventListener('keydown', onEvent);
    };
  }, []);

  return (
    <details className={`dash-popover ${className ?? ''}`} ref={ref}>
      <summary className={buttonClassName} title={title}>{label}</summary>
      <div className={`dash-popover-panel ${panelClassName ?? ''}`}>{children(close)}</div>
    </details>
  );
}
