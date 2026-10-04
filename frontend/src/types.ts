export interface Location {
  item_index: number;
  item_name: string;
  member?: string;
}

export interface ExtractionEvent {
  seq: number;
  item_index: number;
  item_name: string;
  member: string;
  member_header_offset: number;
  triggered_by: string[];
  scope: string;
  round: number;
  location: Location;
}

export interface RoundEvidence {
  scope: string;
  item_index: number;
  round: number;
  undefined_before: string[];
  extracted: Array<{
    member: string;
    item_index?: number;
    triggered_by: string[];
  }>;
}

export interface Decision {
  type: "supersede" | "ignore_later_definition";
  symbol: string;
  chosen: { location: Location; strength: string };
  superseded?: { location: Location; strength: string };
  ignored?: { location: Location; strength: string };
  rule: string;
  seq: number;
}

export interface Rejection {
  rule: string;
  location: Location;
  symbol: string | null;
  detail: {
    reason?: string;
    parser?: string;
    all_undefined?: string[];
    reference_sites?: Record<string, Location[]>;
    existing_provider?: { location: Location; strength: string };
    rejected_provider?: { location: Location; strength: string };
    [key: string]: unknown;
  };
}

export interface InputMeta {
  position: number;
  name: string;
  kind: "object" | "archive" | "unparseable";
  grouped: boolean;
  size: number;
  sha256: string;
  symbols?: Array<{ name: string; kind: string }>;
  defined_symbol_count?: number;
  members?: Array<{
    name: string;
    header_offset: number;
    size: number;
    indexed_symbols: string[];
  }>;
  index_entries?: number;
}

export interface Conclusion {
  audit_id: string;
  status: "accepted" | "rejected";
  message?: string;
  rejection?: Rejection;
  extraction_order: ExtractionEvent[];
  rounds: RoundEvidence[];
  decisions: Decision[];
  events?: Array<Record<string, unknown>>;
  weak_unresolved?: Array<{ symbol: string; reference_sites: Location[] }>;
  defined_symbols?: string[];
  undefined_at_failure?: string[];
  input_fingerprint: string;
  inputs: InputMeta[];
  reopened?: boolean;
  frozen_at?: number;
}

export interface ItemDraft {
  name: string;
  grouped: boolean;
  contentBase64: string;
  fileName: string | null;
}
