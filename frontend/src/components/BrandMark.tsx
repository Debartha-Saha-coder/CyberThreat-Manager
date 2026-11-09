interface BrandMarkProps {
  className?: string
}

export function BrandMark({ className }: BrandMarkProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 120 120"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M13 21h94L91 36H72l16 13v39l-27 26V58L44 42H24L13 21Z" fill="currentColor" />
      <path d="M16 87c2 18 37 2 60-18s33-43 25-52c-7-8-26 2-37 11" fill="none" stroke="var(--accent)" strokeWidth="5" strokeLinecap="round" />
      <path d="m107 15 2.5 8.5L118 26l-8.5 2.5L107 37l-2.5-8.5L96 26l8.5-2.5L107 15Z" fill="var(--accent)" />
    </svg>
  )
}
