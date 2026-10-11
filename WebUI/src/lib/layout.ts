export type ResizeBounds = { readonly min: number; readonly max: number };

export function panelBounds(
  panel: 'navigation' | 'activity',
  viewportWidth: number,
  oppositeWidth: number,
): ResizeBounds {
  if (panel === 'activity') {
    return { min: 280, max: Math.max(280, Math.min(540, viewportWidth - oppositeWidth - 500)) };
  }
  return {
    min: 174,
    max: Math.max(174, Math.min(320, viewportWidth - (viewportWidth > 1100 ? oppositeWidth + 500 : 420))),
  };
}

export function activityHeightBounds(viewportHeight: number, reservedHeight: number): ResizeBounds {
  const max = Math.max(160, Math.min(750, viewportHeight - reservedHeight));
  return { min: Math.min(220, max), max };
}

export function clampPanelWidth(width: number, bounds: ResizeBounds): number {
  return Math.max(bounds.min, Math.min(bounds.max, width));
}
