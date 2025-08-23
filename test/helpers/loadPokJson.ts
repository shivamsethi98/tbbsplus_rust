import fs from "fs";

export type Hex = `0x${string}`;

export interface RustPokJson {
  messageCount: number;
  g1: Hex; h0: Hex; H: Hex[];
  APrime: Hex; ABar: Hex; d: Hex;
  T1: Hex; T2: Hex;
  revealedIdx: number[];
  revealedVals: string[]; // decimal or 0x hex
  challenge: string; // decimal or 0x hex
  respA: string; respH0: string; respR3: string; respSPrime: string;
  respMsgs: string[];
  // Optional encryption relation
  Ybar?: Hex;
  T1enc?: Hex;
  T2enc?: Hex;
  Tenc?: Hex;
  respA3?: string;
  respK?: string;
}

export function loadPokJson(filePath: string): RustPokJson {
  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw) as RustPokJson;
}
