import { submitAudit, reopenAudit, isConclusion, type ApiError } from "./api";
import type {
  Conclusion,
  ItemDraft,
  RoundEvidence,
} from "./types";
import "./styles.css";

const MAX_ITEMS = 12;

const state: {
  auditId: string;
  items: ItemDraft[];
  busy: boolean;
  error: string | null;
  conclusion: Conclusion | null;
} = {
  auditId: "",
  items: [blankItem()],
  busy: false,
  error: null,
  conclusion: null,
};

function blankItem(): ItemDraft {
  return { name: "", grouped: false, contentBase64: "", fileName: null };
}

function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | EventListenerOrEventListenerObject> = {},
  ...children: Array<Node | string>
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = String(v);
    else if (k.startsWith("on") && typeof v === "function") {
      el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    } else if (typeof v === "boolean") {
      if (v) el.setAttribute(k, "");
    } else {
      el.setAttribute(k, String(v));
    }
  }
  for (const c of children) el.append(c instanceof Node ? c : document.createTextNode(c));
  return el;
}

function render(): void {
  const root = document.getElementById("app")!;
  root.innerHTML = "";
  root.append(renderHeader(), renderMain());
}

function renderHeader(): HTMLElement {
  return h(
    "header",
    {},
    h("h1", {}, "机载维护镜像 · 离线装载链接审计"),
    h(
      "p",
      {},
      "小端 x86-64 · ELF64 ET_REL 对象 / GNU ar 归档（未压缩）· 左至右链接语义 · 强/弱定义裁决 · 成组归档不动点",
    ),
  );
}

function renderMain(): HTMLElement {
  const main = h("main");
  const grid = h("div", { class: "grid" });
  grid.append(renderFormColumn(), renderEvidenceColumn());
  main.append(grid);
  return main;
}

// -- form column -------------------------------------------------------------

function renderFormColumn(): HTMLElement {
  const col = h("div");

  const idPanel = h("div", { class: "panel" });
  idPanel.append(
    h("h2", {}, "① 稳定审计标识"),
    h(
      "label",
      { class: "field" },
      h("span", {}, "AUDIT_ID（1–64 位字母/数字/._-，用于冻结与重开结论）"),
      input(state.auditId, "例如 ACMAINT-2026.10-0007", (v) => {
        state.auditId = v;
      }),
    ),
    h(
      "div",
      { class: "row" },
      h(
        "button",
        {
          class: "secondary",
          onclick: async () => {
            if (!state.auditId.trim()) {
              state.error = "请填写要重开的审计标识";
              render();
              return;
            }
            state.busy = true;
            state.error = null;
            render();
            const r = await reopenAudit(state.auditId.trim());
            state.busy = false;
            if (r.status === 200 && isConclusion(r.body)) {
              state.conclusion = r.body;
            } else {
              state.error = `重开失败：${(r.body as ApiError).message}`;
            }
            render();
          },
        },
        "按标识重开冻结结论",
      ),
      h("span", { class: "muted" }, "重开返回的是冻结时的同一裁决（含 reopened 标记）"),
    ),
  );
  col.append(idPanel);

  const itemsPanel = h("div", { class: "panel" });
  itemsPanel.append(
    h("h2", {}, `② 命令行顺序输入（至多 ${MAX_ITEMS} 个，Base64）`),
    h("p", { class: "muted", style: "margin-top:-6px" },
      "勾选“成组”的连续条目构成一个 --start-group/--end-group：组内归档被整轮反复扫描，直到未定义集合不再变化；非连续勾选各自成组。"),
  );
  state.items.forEach((item, idx) => itemsPanel.append(renderItemCard(item, idx)));
  itemsPanel.append(
    h(
      "div",
      { class: "row" },
      h(
        "button",
        {
          class: "secondary",
          onclick: () => {
            if (state.items.length < MAX_ITEMS) {
              state.items.push(blankItem());
              render();
            }
          },
        },
        "+ 添加输入",
      ),
      h(
        "button",
        {
          onclick: async () => {
            state.error = null;
            if (!state.auditId.trim()) {
              state.error = "请先填写稳定审计标识";
              render();
              return;
            }
            const filled = state.items.filter((i) => i.contentBase64.trim());
            if (!filled.length) {
              state.error = "至少需要一个 ELF 对象或 ar 归档";
              render();
              return;
            }
            for (const [i, it] of state.items.entries()) {
              if (!it.contentBase64.trim()) continue;
              if (!it.name.trim()) {
                it.name = it.fileName ?? `input${i + 1}`;
              }
            }
            state.busy = true;
            render();
            const r = await submitAudit(state.auditId.trim(), filled);
            state.busy = false;
            if ((r.status === 200 || r.status === 201) && isConclusion(r.body)) {
              state.conclusion = r.body;
              state.error = null;
            } else {
              const e = r.body as ApiError;
              state.error = r.status === 409
                ? `审计标识已被不同输入冻结（409）：${e.message}`
                : `请求被拒绝（${r.status}）：${e.message}`;
            }
            render();
          },
        },
        state.busy ? "审计中…" : "③ 提交并冻结裁决",
      ),
      state.busy ? h("span", { class: "pending" }, "正在以原始字节校验边界、索引与符号表…") : "",
    ),
  );
  if (state.error) {
    itemsPanel.append(h("p", { class: "error-text" }, state.error));
  }
  col.append(itemsPanel);
  return col;
}

function input(
  value: string,
  placeholder: string,
  onInput: (v: string) => void,
): HTMLElement {
  return h("input", {
    type: "text",
    value,
    placeholder,
    oninput: (e: Event) => onInput((e.target as HTMLInputElement).value),
  });
}

function renderItemCard(item: ItemDraft, idx: number): HTMLElement {
  const card = h("div", { class: "item-card" + (item.grouped ? " grouped" : "") });
  const head = h("div", { class: "item-head" });
  head.append(
    h("span", { class: "pos" }, String(idx + 1)),
    h("input", {
      type: "text",
      placeholder: `成员/对象名（缺省取文件名 input${idx + 1}）`,
      value: item.name,
      oninput: (e: Event) => {
        item.name = (e.target as HTMLInputElement).value;
      },
    }),
    h(
      "label",
      { class: "check" },
      h("input", {
        type: "checkbox",
        ...(item.grouped ? { checked: true } : {}),
        onchange: (e: Event) => {
          item.grouped = (e.target as HTMLInputElement).checked;
          render();
        },
      }),
      "成组 (--start-group)",
    ),
  );
  if (idx > 0 || state.items.length > 1) {
    head.append(
      h(
        "button",
        {
          class: "danger",
          onclick: () => {
            state.items.splice(idx, 1);
            render();
          },
        },
        "删除",
      ),
    );
  }
  card.append(head);

  const fileInput = h("input", {
    type: "file",
    onchange: async (e: Event) => {
      const f = (e.target as HTMLInputElement).files?.[0];
      if (!f) return;
      item.fileName = f.name;
      item.contentBase64 = await fileToBase64(f);
      if (!item.name) item.name = f.name;
      render();
    },
  }) as HTMLInputElement;

  card.append(
    h("label", { class: "field" }, h("span", {}, "选择 .o / .a 文件（自动 Base64 编码）"), fileInput),
    h(
      "label",
      { class: "field" },
      h("span", {}, "或直接粘贴 Base64"),
      (() => {
        const ta = h("textarea", {
          placeholder: "粘贴 ELF64 ET_REL 或 GNU ar 的 Base64…",
          oninput: (e: Event) => {
            item.contentBase64 = (e.target as HTMLTextAreaElement).value.trim();
          },
        }) as HTMLTextAreaElement;
        ta.value = item.contentBase64;
        return ta;
      })(),
    ),
  );
  if (item.contentBase64) {
    card.append(
      h(
        "div",
        { class: "meta-line" },
        `已载入 ${item.fileName ? item.fileName + " · " : ""}${Math.round(item.contentBase64.length * 3 / 4)} 字节`,
      ),
    );
  }
  return card;
}

// -- evidence column ---------------------------------------------------------

function renderEvidenceColumn(): HTMLElement {
  const col = h("div");
  const c = state.conclusion;
  if (!c) {
    col.append(
      h(
        "div",
        { class: "panel pending" },
        "提交后，这里将通过真实 API 展示：裁决结论、首次触发位置、抽取成员顺序、每轮未定义集合、强弱定义取舍与归档/成员清册。",
      ),
    );
    return col;
  }

  col.append(renderVerdictBanner(c));

  const ext = h("div", { class: "panel" });
  ext.append(h("h2", {}, "抽取顺序（Extraction Order）"));
  if (c.extraction_order.length) {
    const table = h("table");
    table.append(
      h("thead", {}, h("tr", {},
        h("th", {}, "#"), h("th", {}, "命令行位置"), h("th", {}, "成员"),
        h("th", {}, "触发符号"), h("th", {}, "轮次/范围"))),
    );
    const tbody = h("tbody");
    c.extraction_order.forEach((e, i) => {
      tbody.append(
        h("tr", {},
          h("td", { class: "mono" }, String(i + 1)),
          h("td", { class: "mono" }, `#${e.item_index} ${e.item_name}`),
          h("td", { class: "mono" }, e.member),
          h("td", { class: "mono" }, e.triggered_by.map((s) => s).join(", ")),
          h("td", { class: "mono" }, `${e.scope} r${e.round}`)),
      );
    });
    table.append(tbody);
    ext.append(table);
  } else {
    ext.append(h("p", { class: "muted" }, "没有任何归档成员被抽取。"));
  }
  col.append(ext);

  col.append(renderRounds(c));
  col.append(renderDecisions(c));
  col.append(renderInputs(c));
  col.append(renderMeta(c));
  return col;
}

function renderVerdictBanner(c: Conclusion): HTMLElement {
  const accepted = c.status === "accepted";
  const banner = h("div", { class: `banner ${c.status}` });
  banner.append(
    h(
      "h3",
      {},
      accepted ? "✔ 裁决：接受装载（链接闭合）" : "✘ 裁决：拒绝装载",
      h("span", { class: accepted ? "big-ok" : "big-err" }, ""),
    ),
  );
  const dl = h("dl", { class: "kv" });
  dl.append(
    h("dt", {}, "审计标识"), h("dd", {}, c.audit_id),
    h("dt", {}, "状态"), h("dd", {}, c.status),
  );
  if (c.reopened) dl.append(h("dt", {}, "说明"), h("dd", {}, "按标识重开的冻结结论（同一裁决）"));
  if (c.frozen_at) {
    dl.append(h("dt", {}, "冻结时间"), h("dd", {}, new Date(c.frozen_at * 1000).toISOString()));
  }
  banner.append(dl);

  if (!accepted && c.rejection) {
    const r = c.rejection;
    banner.append(
      h("p", {}, c.message ?? "链接裁决失败"),
      h("p", {}, "规则 ", h("span", { class: "rule" }, r.rule)),
      h(
        "dl",
        { class: "kv" },
        h("dt", {}, "首次触发位置"),
        h(
          "dd",
          {},
          `命令行 #${r.location.item_index} ${r.location.item_name}` +
            (r.location.member ? ` 内成员 ${r.location.member}` : ""),
        ),
        h("dt", {}, "相关符号"),
        h("dd", {}, r.symbol ?? "—"),
      ),
    );
    if (r.detail.all_undefined) {
      banner.append(
        h("p", { class: "mono" }, "最终未定义集合：" + r.detail.all_undefined.join(", ")),
      );
    }
  }
  if (accepted && c.undefined_at_failure?.length === 0) {
    banner.append(h("p", { class: "muted" }, "无最终未定义符号。"));
  }
  if (c.weak_unresolved?.length) {
    banner.append(
      h(
        "p",
        { class: "muted" },
        "弱引用未定义（不阻断装载）：" + c.weak_unresolved.map((w) => w.symbol).join(", "),
      ),
    );
  }
  return banner;
}

function renderRounds(c: Conclusion): HTMLElement {
  const panel = h("div", { class: "panel" });
  panel.append(h("h2", {}, "每轮证据：未定义集合 → 抽取成员"));
  const table = h("table");
  table.append(
    h("thead", {}, h("tr", {},
      h("th", {}, "范围"), h("th", {}, "归档位置"), h("th", {}, "轮"),
      h("th", {}, "轮前未定义集合"), h("th", {}, "本轮抽取"))),
  );
  const tbody = h("tbody");
  const fmtRound = (r: RoundEvidence) => {
    const scopeLabel = r.scope === "group" ? "成组整轮" : `归档 #${r.item_index}`;
    const itemLabel = r.scope === "group"
      ? `组起始 #${r.item_index}`
      : `#${r.item_index}`;
    tbody.append(
      h("tr", {},
        h("td", { class: "mono" }, scopeLabel),
        h("td", { class: "mono" }, itemLabel),
        h("td", { class: "mono" }, String(r.round)),
        h("td", { class: "mono" }, r.undefined_before.length ? r.undefined_before.join(", ") : "∅"),
        h("td", { class: "mono" },
          r.extracted.length
            ? r.extracted
                .map((x) => `${x.item_index ? "#" + x.item_index + " " : ""}${x.member}${x.triggered_by.length ? " ← {" + x.triggered_by.join(",") + "}" : ""}`)
                .join("; ")
            : "—（不动点轮）")),
    );
  };
  c.rounds.forEach(fmtRound);
  table.append(tbody);
  panel.append(table);
  return panel;
}

function renderDecisions(c: Conclusion): HTMLElement {
  const panel = h("div", { class: "panel" });
  panel.append(h("h2", {}, "定义裁决（强 > COMMON > 弱，同位先到先得）"));
  if (!c.decisions.length) {
    panel.append(h("p", { class: "muted" }, "无冲突，未发生取舍。"));
    return panel;
  }
  const table = h("table");
  table.append(
    h("thead", {}, h("tr", {},
      h("th", {}, "符号"), h("th", {}, "裁决"), h("th", {}, "选中定义"),
      h("th", {}, "舍弃/覆盖"), h("th", {}, "规则"))),
  );
  const tbody = h("tbody");
  c.decisions.forEach((d) => {
    const loser = d.superseded ?? d.ignored;
    tbody.append(
      h("tr", {},
        h("td", { class: "mono" }, d.symbol),
        h("td", {}, d.type === "supersede" ? "后者取代前者" : "保留前者"),
        h("td", { class: "mono" },
          `${strengthTag(d.chosen.strength)} ${loc(d.chosen.location)}`),
        h("td", { class: "mono" }, loser ? `${strengthTag(loser.strength)} ${loc(loser.location)}` : "—"),
        h("td", { class: "mono" }, d.rule)),
    );
  });
  table.append(tbody);
  panel.append(table);
  return panel;
}

function strengthTag(s: string): HTMLElement {
  return h("span", { class: `tag ${s}` }, s);
}

function loc(l: { item_index: number; item_name: string; member?: string }): string {
  return `#${l.item_index} ${l.item_name}${l.member ? `:${l.member}` : ""}`;
}

function renderInputs(c: Conclusion): HTMLElement {
  const panel = h("div", { class: "panel" });
  panel.append(h("h2", {}, "输入清册（原始字节校验结果）"));
  c.inputs.forEach((inp) => {
    const wrap = h("div", { style: "margin-bottom:14px" });
    wrap.append(
      h("div", {},
        h("span", { class: "pos" }, String(inp.position)),
        h("strong", {}, inp.name + " "),
        h("span", { class: `tag ${inp.kind}` }, inp.kind),
        inp.grouped ? h("span", { class: "tag weak" }, "grouped") : "",
        h("span", { class: "meta-line" }, ` ${inp.size} B`),
      ),
      h("div", { class: "meta-line" }, "sha256: " + inp.sha256),
    );
    if (inp.kind === "archive" && inp.members) {
      const lines = inp.members.map(
        (m) => `${m.name} [idx: {${m.indexed_symbols.join(",") || "—"}}] @${m.header_offset}`,
      );
      wrap.append(h("div", { class: "meta-line" }, lines.join("\n")));
    }
    if (inp.kind === "object" && inp.symbols) {
      const tags = h("div", { class: "sym-list" });
      inp.symbols.forEach((s) => {
        tags.append(h("span", { class: `tag ${s.kind}` }, `${s.name} · ${s.kind}`));
      });
      wrap.append(tags);
    }
    panel.append(wrap);
  });
  return panel;
}

function renderMeta(c: Conclusion): HTMLElement {
  return h(
    "div",
    { class: "panel" },
    h("h2", {}, "输入指纹"),
    h("p", { class: "fingerprint" }, c.input_fingerprint),
  );
}

export function start(): void {
  render();
}
