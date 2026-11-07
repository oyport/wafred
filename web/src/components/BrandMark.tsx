import type { ImgHTMLAttributes } from 'react'

/** Reuse the browser favicon so the in-app brand mark stays identical. */
export function BrandMark(props: Omit<ImgHTMLAttributes<HTMLImageElement>, 'src' | 'alt'>) {
  return <img src="/favicon.svg" alt="" aria-hidden="true" {...props} />
}
