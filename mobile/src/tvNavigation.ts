/**
 * Android TV 遥控器（D-pad）空间导航。
 *
 * 背景：Android WebView 默认把方向键当成「滚动页面」，不会移动焦点；
 * TauriActivity 也不会替 WebView 处理按键。电视盒子上没有触摸，
 * 于是所有控件都无法操作。
 *
 * 做法：捕获方向键 → 按几何位置在可聚焦元素间移动焦点 → Enter/DPAD_CENTER 触发点击。
 * 细则：
 *  - 以「控件容器」（.v-input/.v-checkbox/.v-slider/.v-btn/.v-list-item）为几何单元，
 *    避免在同一个输入框内部的 input 与眼睛图标之间来回跳；
 *  - 垂直移动时给「横向重叠度高」的候选加权，表单里不会从右上角直接跳到右下角；
 *  - 输入框保留左右（光标）、滑块保留左右（调值）；
 *  - 下拉框（combobox）关闭时把 ↓ 让给它展开菜单，展开后全部放行；
 *  - 复选框/单选框用 Enter 切换（浏览器原生只认空格）。
 */

type Dir = 'up' | 'down' | 'left' | 'right';

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[role="slider"]',
  '[role="combobox"]',
  '[role="button"]',
  '[tabindex]:not([tabindex="-1"])',
  '.v-list-item',
].join(',');

/** 组件自己管理焦点的容器（下拉菜单、对话框） */
const OVERLAY_SELECTOR = [
  '.v-overlay-container',
  '.v-overlay',
  '.v-menu',
  '[role="listbox"]',
  '[role="menu"]',
  '[role="dialog"]',
  '.v-dialog',
].join(',');

/** 一个「控件」的范围：用于几何计算与去重 */
const CONTROL_SELECTOR = [
  '.v-input',
  '.v-checkbox',
  '.v-slider',
  '.v-btn',
  '.v-list-item',
  '.v-select',
  '.v-autocomplete',
  '.v-combobox',
].join(',');

const NATIVELY_ACTIVATABLE = /^(BUTTON|A|INPUT|SELECT|TEXTAREA)$/;

const KEY: Record<Dir, [string, number]> = {
  up: ['ArrowUp', 19],
  down: ['ArrowDown', 20],
  left: ['ArrowLeft', 21],
  right: ['ArrowRight', 22],
};

function isVisible(el: HTMLElement): boolean {
  if (el.hasAttribute('disabled') || el.getAttribute('aria-hidden') === 'true') return false;
  const rect = el.getBoundingClientRect();
  if (rect.width < 2 || rect.height < 2) return false;
  const style = window.getComputedStyle(el);
  // 注意：Vuetify 的 checkbox/radio 把真实 input 设成 opacity:0，
  // 不能用 opacity 判定不可见，否则遥控器永远选不中复选框。
  return style.visibility !== 'hidden' && style.display !== 'none';
}

function controlOf(el: HTMLElement): HTMLElement {
  return (el.closest(CONTROL_SELECTOR) as HTMLElement | null) ?? el;
}

function focusables(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(isVisible);
}

function ensureFocusable(el: HTMLElement) {
  if (!el.hasAttribute('tabindex') && !NATIVELY_ACTIVATABLE.test(el.tagName)) {
    el.setAttribute('tabindex', '0');
  }
}

function rectCenter(rect: DOMRect) {
  return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
}

/** 候选去重：同一个控件容器只保留第一个可聚焦元素 */
function candidates(from: HTMLElement | null): Array<{ el: HTMLElement; rect: DOMRect }> {
  const seen = new Set<HTMLElement>();
  const fromControl = from ? controlOf(from) : null;
  const out: Array<{ el: HTMLElement; rect: DOMRect }> = [];

  for (const el of focusables()) {
    const control = controlOf(el);
    if (fromControl && control === fromControl) continue;
    if (seen.has(control)) continue;
    seen.add(control);
    out.push({ el, rect: control.getBoundingClientRect() });
  }
  return out;
}

function findTarget(dir: Dir, from: HTMLElement | null): HTMLElement | null {
  const list = candidates(from);
  if (list.length === 0) return null;
  if (!from) return dir === 'up' ? list[list.length - 1].el : list[0].el;

  const cur = controlOf(from).getBoundingClientRect();
  const curC = rectCenter(cur);
  let best: HTMLElement | null = null;
  let bestScore = Number.POSITIVE_INFINITY;

  for (const { el, rect } of list) {
    const c = rectCenter(rect);
    const dx = c.x - curC.x;
    const dy = c.y - curC.y;

    let primary: number;
    let secondary: number;
    let overlap: number; // 0..1，垂直于移动方向上的投影重叠比例

    if (dir === 'right' || dir === 'left') {
      if (dir === 'right' ? dx < 8 : dx > -8) continue;
      primary = Math.abs(dx);
      secondary = Math.abs(dy);
      const lo = Math.max(rect.top, cur.top);
      const hi = Math.min(rect.bottom, cur.bottom);
      overlap = Math.max(0, hi - lo) / Math.max(1, Math.min(rect.height, cur.height));
    } else {
      if (dir === 'down' ? dy < 8 : dy > -8) continue;
      primary = Math.abs(dy);
      secondary = Math.abs(dx);
      const lo = Math.max(rect.left, cur.left);
      const hi = Math.min(rect.right, cur.right);
      overlap = Math.max(0, hi - lo) / Math.max(1, Math.min(rect.width, cur.width));
    }

    // 主距离 + 正交距离惩罚 - 同轴重叠奖励（表单里优先「下一行同一个字段」）
    const score = primary + secondary * 1.6 - Math.min(overlap, 1) * 260;
    if (score < bestScore) {
      bestScore = score;
      best = el;
    }
  }
  return best;
}

function focusElement(el: HTMLElement) {
  ensureFocusable(el);
  el.focus({ preventScroll: true });
  try {
    el.scrollIntoView({ block: 'nearest', inline: 'nearest', behavior: 'smooth' });
  } catch {
    el.scrollIntoView(false);
  }
}

function activeElement(): HTMLElement | null {
  const el = document.activeElement as HTMLElement | null;
  return el && el !== document.body ? el : null;
}

function inOverlay(el: HTMLElement | null): boolean {
  if (!el) return false;
  if (el.closest(OVERLAY_SELECTOR)) return true;
  return el.getAttribute('aria-expanded') === 'true';
}

const isEditable = (el: HTMLElement | null) =>
  !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA');

const isSlider = (el: HTMLElement | null) => !!el && el.getAttribute('role') === 'slider';

const isCombobox = (el: HTMLElement | null) =>
  !!el && (el.getAttribute('role') === 'combobox' || !!el.closest('.v-autocomplete, .v-combobox, .v-select'));

const isToggle = (el: HTMLElement | null) =>
  !!el && el.tagName === 'INPUT' && (el as HTMLInputElement).type === 'checkbox';

const isRadio = (el: HTMLElement | null) =>
  !!el && el.tagName === 'INPUT' && (el as HTMLInputElement).type === 'radio';

function handleEnter(e: KeyboardEvent, el: HTMLElement | null): boolean {
  // 23 = KEYCODE_DPAD_CENTER（部分机型原样上报，浏览器不会把它当 Enter 激活元素）
  const isDpadCenter = e.keyCode === 23;
  const isEnter =
    e.key === 'Enter' || e.key === 'Select' || e.keyCode === 13 || isDpadCenter;
  if (!isEnter || !el) return false;

  // 复选框/单选框：浏览器原生只认空格，遥控器只有 Enter
  if (isToggle(el) || isRadio(el)) {
    e.preventDefault();
    el.click();
    return true;
  }
  // 原生按钮/链接：标准 Enter 交给浏览器（避免双触发）；DPAD_CENTER 得自己点
  if (NATIVELY_ACTIVATABLE.test(el.tagName) && !isDpadCenter) return false;
  e.preventDefault();
  el.click();
  return true;
}

export function installTvNavigation() {
  if (typeof window === 'undefined') return;
  const w = window as unknown as { __tvNavInstalled?: boolean };
  if (w.__tvNavInstalled) return;
  w.__tvNavInstalled = true;

  window.addEventListener(
    'keydown',
    (event) => {
      const e = event as KeyboardEvent;
      const el = activeElement();

      // 下拉菜单/对话框展开时，方向键归组件自己处理
      if (inOverlay(el)) return;

      if (handleEnter(e, el)) return;

      let dir: Dir | null = null;
      for (const name of Object.keys(KEY) as Dir[]) {
        const [key, code] = KEY[name];
        if (e.key === key || e.keyCode === code) {
          dir = name;
          break;
        }
      }
      if (!dir) return;

      // 输入框保留左右（光标）；滑块保留左右（调节数值）
      if ((isEditable(el) || isSlider(el)) && (dir === 'left' || dir === 'right')) return;

      // 滑块会把 ↑/↓ 也当成调值，这里必须拦住，否则焦点永远离不开滑块
      if (isSlider(el)) {
        e.preventDefault();
        e.stopPropagation();
      }

      const target = findTarget(dir, el);
      if (!target) return;

      e.preventDefault();
      e.stopPropagation();
      focusElement(target);
    },
    true,
  );

  // 首次进入页面时把焦点交到第一个“可输入/可调”的控件，遥控器立刻可用
  window.setTimeout(() => {
    if (activeElement()) return;
    const all = focusables();
    const preferred =
      all.find((x) => x.tagName === 'INPUT' && (x as HTMLInputElement).type !== 'checkbox') ??
      all.find((x) => x.getAttribute('role') === 'combobox' || x.getAttribute('role') === 'slider') ??
      all[0];
    if (preferred) focusElement(preferred);
  }, 600);
}
