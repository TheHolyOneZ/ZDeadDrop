import { useEffect, useState } from "react";
import { sealSvg } from "../lib/api";
import type { SealState } from "../lib/types";

interface Props {
  seed: string;
  state: SealState;
  size: number;

  simplified?: boolean;
  className?: string;
}

export function Seal({ seed, state, size, simplified = false, className }: Props) {
  const [svg, setSvg] = useState<string>("");

  useEffect(() => {
    let live = true;
    sealSvg(seed, state, size, simplified)
      .then((markup) => {
        if (live) setSvg(markup);
      })
      .catch(() => {
        if (live) setSvg("");
      });
    return () => {
      live = false;
    };
  }, [seed, state, size, simplified]);

  if (!svg) {
    return (
      <div
        className={`seal seal--pending ${className ?? ""}`}
        style={{ width: size, height: size }}
        aria-hidden="true"
      />
    );
  }

  return (
    <div
      className={`seal ${className ?? ""}`}
      style={{ width: size, height: size }}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
