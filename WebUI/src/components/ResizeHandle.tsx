import { useRef, type PointerEvent as ReactPointerEvent, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import { clampPanelWidth, type ResizeBounds } from '../lib/layout';

type ResizeHandleProps = {
  readonly className: string;
  readonly label: string;
  readonly controls: string;
  readonly value: number;
  readonly direction: 1 | -1;
  readonly axis?: 'horizontal' | 'vertical';
  readonly bounds: () => ResizeBounds;
  readonly onResize: (size: number) => void;
};

export function ResizeHandle({ className, label, controls, value, direction, axis = 'horizontal', bounds, onResize }: ResizeHandleProps) {
  const drag = useRef<{ pointerId: number; coordinate: number; size: number } | null>(null);
  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    drag.current = { pointerId: event.pointerId, coordinate: axis === 'horizontal' ? event.clientX : event.clientY, size: value };
    event.currentTarget.dataset.pointerFocused = 'true';
    event.currentTarget.setPointerCapture(event.pointerId);
    event.preventDefault();
  };
  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!drag.current || drag.current.pointerId !== event.pointerId) return;
    const coordinate = axis === 'horizontal' ? event.clientX : event.clientY;
    onResize(clampPanelWidth(drag.current.size + (coordinate - drag.current.coordinate) * direction, bounds()));
  };
  const endPointer = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (drag.current?.pointerId !== event.pointerId) return;
    drag.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const decrease = axis === 'horizontal' ? 'ArrowLeft' : 'ArrowUp';
    const increase = axis === 'horizontal' ? 'ArrowRight' : 'ArrowDown';
    if (event.key !== decrease && event.key !== increase && event.key !== 'Home' && event.key !== 'End') return;
    event.preventDefault();
    delete event.currentTarget.dataset.pointerFocused;
    const limit = bounds();
    const size = event.key === 'Home' ? limit.min : event.key === 'End' ? limit.max
      : value + (event.key === increase ? 16 : -16) * direction;
    onResize(clampPanelWidth(size, limit));
  };
  const limits = bounds();
  return <div
    className={`panel-resizer ${className}`}
    role="separator"
    tabIndex={0}
    aria-label={label}
    aria-orientation={axis === 'horizontal' ? 'vertical' : 'horizontal'}
    aria-controls={controls}
    aria-valuemin={limits.min}
    aria-valuemax={limits.max}
    aria-valuenow={value}
    onPointerDown={onPointerDown}
    onPointerMove={onPointerMove}
    onPointerUp={endPointer}
    onPointerCancel={endPointer}
    onKeyDown={onKeyDown}
    onBlur={event => { delete event.currentTarget.dataset.pointerFocused; }}
  />;
}
