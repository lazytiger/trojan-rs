/**
 * adaptive-css：让同一份 APK 同时适配「支持 / 不支持 CSS 级联层」的 WebView。
 *
 * 背景：Vuetify 4 把全部组件样式包在 `@layer` 里。Chromium < 99 的 WebView 不认识 `@layer`，
 * 会把整个 block 丢弃（本项目 99.93% 的 CSS 都在里面）→ 界面看起来像「CSS 没加载」。
 *
 * 做法：
 *   1. 构建时额外产出一份 legacy CSS：
 *        - 按 Vuetify 官方层序摊平 @layer
 *        - 给「overrides 及以上」的规则补一级 ID 特异性（:not(#\9)），还原
 *          「层级优先于特异性」的语义，避免摊平后工具类输给组件状态类
 *        - color-mix() 补一条回退声明
 *        - dvh → vh
 *   2. 内联脚本在首屏前探测能力，二选一加载：
 *        - 支持 @layer 且支持 color-mix → 原始 CSS（保真）
 *        - 否则                          → legacy CSS（兼容）
 */
import postcss from 'postcss';

/** Vuetify 4 官方层序：core → components → overrides → utilities → final */
const LAYER_ORDER = [
  'core.reset', 'core.base', 'components', 'overrides',
  'utilities.theme-base', 'utilities.typography', 'utilities.helpers',
  'utilities.theme-background', 'utilities.theme-foreground',
  'final.transitions', 'final.trumps',
];

/** 从这个层级开始补特异性（overrides 及其后所有层） */
const BUMP_FROM_RANK = 3;
const BUMP = ':not(#\\9)';

function layerRank(name) {
  const i = LAYER_ORDER.indexOf(name.replace(/^vuetify-/, ''));
  return i === -1 ? 998 : i;
}

/** 把 :not(#\9) 插到伪元素之前（伪元素后不能再跟别的选择器） */
function bumpSelector(selector) {
  if (!selector || selector.includes(BUMP.trim())) return selector;
  const pe = selector.match(/::[a-zA-Z-]+(\([^)]*\))?/);
  if (pe) return selector.slice(0, pe.index) + BUMP + selector.slice(pe.index);
  return selector + BUMP;
}

/** 递归收集 @layer 块（含 `a.b` 形式与嵌套形式），并从父节点摘除 */
function takeLayers(container, prefix = '') {
  const found = [];
  container.each((node) => {
    if (node.type === 'atrule' && node.name === 'layer') {
      const name = (prefix ? `${prefix}.` : '') + node.params.trim();
      if (node.nodes) {
        const nested = takeLayers(node, name);
        found.push({ name, nodes: node.nodes, nested });
      }
      node.remove();
    }
  });
  return found;
}

function flattenLayers(root) {
  const blocks = [];

  // 展平嵌套：把子层拆成独立条目，父层只保留非 layer 节点
  const collect = (items) => {
    for (const b of items) {
      if (b.nested && b.nested.length) {
        collect(b.nested);
        // 父层保留自己剩余的节点
      }
      if (b.nodes && b.nodes.length) blocks.push(b);
    }
  };
  collect(takeLayers(root));

  // 语句式 @layer a,b; 直接删掉
  root.walkAtRules('layer', (at) => {
    if (!at.nodes) at.remove();
  });

  blocks.sort((a, b) => layerRank(a.name) - layerRank(b.name));

  const out = postcss.root();
  for (const block of blocks) {
    const rank = layerRank(block.name);
    for (const node of block.nodes) {
      if (rank >= BUMP_FROM_RANK) {
        if (node.type === 'rule') {
          node.selectors = node.selectors.map(bumpSelector);
        } else if (node.nodes) {
          node.walkRules((rule) => {
            rule.selectors = rule.selectors.map(bumpSelector);
          });
        }
      }
      out.append(node.clone());
    }
  }
  // 层外规则（应用自有样式）放最后，保持它们继续覆盖 Vuetify
  root.each((node) => out.append(node.clone()));
  return out;
}

function colorMixFallback(prop, value) {
  if (prop === 'border-image' || prop === 'border-image-source') return 'none';

  const pct = value.match(/(\d+(?:\.\d+)?)%\s*,\s*transparent/);
  let alpha = null;

  if (prop.indexOf('--v-elevation-overlay') === 0) {
    alpha = pct ? Number(pct[1]) / 100 : 0;
  } else if (/high-emphasis-opacity/.test(value)) {
    alpha = 0.87;
  } else if (/medium-emphasis-opacity/.test(value)) {
    alpha = 0.6;
  } else if (/disabled-opacity/.test(value)) {
    alpha = 0.38;
  } else if (pct) {
    alpha = Number(pct[1]) / 100;
  }

  return alpha === null ? null : `rgba(0,0,0,${Number(alpha.toFixed(3))})`;
}

export function toLegacyCss(css) {
  const root = flattenLayers(postcss.parse(css));

  root.walkDecls((decl) => {
    if (decl.value.includes('dvh')) {
      decl.value = decl.value.replace(/(\d*\.?\d+)dvh\b/g, '$1vh');
    }
    if (!decl.value.includes('color-mix(')) return;
    const fb = colorMixFallback(decl.prop, decl.value);
    if (fb) decl.cloneBefore({ prop: decl.prop, value: fb });
  });

  return root.toString();
}

const LOADER = (pairs) => `<script>
(function () {
  var pairs = ${JSON.stringify(pairs)};
  function layerOK() {
    try {
      var s = new CSSStyleSheet();
      s.replaceSync('@layer a{b{color:red}}');
      return Array.prototype.some.call(s.cssRules, function (r) {
        return r.constructor && r.constructor.name === 'CSSLayerBlockRule';
      });
    } catch (e) { return false; }
  }
  var colorOK = !!(window.CSS && CSS.supports && CSS.supports('color', 'color-mix(in srgb, red 50%, blue)'));
  var layer = layerOK();
  var legacy = !layer || !colorOK;
  window.__cssProbe = { layer: layer, colorMix: colorOK, mode: legacy ? 'legacy' : 'modern' };
  for (var i = 0; i < pairs.length; i++) {
    var l = document.createElement('link');
    l.rel = 'stylesheet';
    l.setAttribute('crossorigin', '');
    l.href = legacy ? pairs[i].l : pairs[i].m;
    document.head.appendChild(l);
  }
  try { console.log('[adaptive-css]', window.__cssProbe); } catch (e) {}
})();
</script>`;

const toText = (s) => (typeof s === 'string' ? s : new TextDecoder().decode(s));

export default function adaptiveCss() {
  return {
    name: 'adaptive-css',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const pairs = [];

      for (const asset of Object.values(bundle)) {
        if (asset.type !== 'asset' || !asset.fileName.endsWith('.css')) continue;
        const modern = toText(asset.source);
        const legacyName = asset.fileName.replace(/\.css$/, '.legacy.css');
        this.emitFile({ type: 'asset', fileName: legacyName, source: toLegacyCss(modern) });
        pairs.push({ m: '/' + asset.fileName, l: '/' + legacyName });
      }
      if (!pairs.length) return;

      for (const asset of Object.values(bundle)) {
        if (asset.type !== 'asset' || !asset.fileName.endsWith('.html')) continue;
        let html = toText(asset.source);
        html = html.replace(/<link[^>]+rel="stylesheet"[^>]*>/g, '');
        html = html.replace('</head>', `${LOADER(pairs)}\n  </head>`);
        asset.source = html;
      }
    },
  };
}
