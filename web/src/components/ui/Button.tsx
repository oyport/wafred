import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'link'
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon'

export interface ButtonBaseProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  icon?: ReactNode
  fullWidth?: boolean
}

/**
 * Icon-only buttons render no text, so they must carry an `aria-label`
 * (axe `button-name`). The union makes omitting it a type error whenever
 * `size="icon"` is used, instead of relying on review to catch it.
 */
export type ButtonProps = ButtonBaseProps &
  (
    | { size: 'icon'; 'aria-label': string }
    | { size?: Exclude<ButtonSize, 'icon'> }
  )

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    'bg-brand text-on-brand border border-transparent hover:bg-brand-hover active:brightness-95 shadow-sm disabled:bg-disabled disabled:text-fg-disabled',
  secondary:
    'bg-elevated text-fg border border-line hover:bg-recessed active:bg-recessed shadow-sm disabled:bg-disabled disabled:text-fg-disabled',
  danger:
    'bg-danger text-on-danger border border-transparent hover:bg-danger-hover active:brightness-95 shadow-sm disabled:bg-disabled disabled:text-fg-disabled',
  ghost:
    'bg-transparent text-fg-subtle border border-transparent hover:bg-recessed hover:text-fg disabled:text-fg-disabled',
  link: 'bg-transparent text-link border border-transparent hover:underline px-0 disabled:text-fg-disabled',
}

const sizeClasses: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-[13px] gap-1.5 rounded-md',
  md: 'h-9 px-4 text-sm gap-2 rounded-md',
  lg: 'h-11 px-5 text-[15px] gap-2 rounded-lg',
  icon: 'h-9 w-9 justify-center rounded-md',
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (props, ref) => {
    // The public type is a union that enforces `aria-label` for icon buttons;
    // the implementation works on the flat shape.
    const {
      className,
      variant = 'secondary',
      size = 'md',
      loading = false,
      icon,
      fullWidth = false,
      children,
      disabled,
      type = 'button',
      ...rest
    } = props as ButtonBaseProps
    return (
      <button
        ref={ref}
        type={type}
        disabled={disabled || loading}
        className={cn(
          'inline-flex items-center whitespace-nowrap font-medium transition-[background-color,color,border-color,box-shadow,transform] duration-150 select-none',
          'disabled:cursor-not-allowed disabled:opacity-100 disabled:shadow-none enabled:active:translate-y-px',
          variantClasses[variant],
          sizeClasses[size],
          size === 'icon' && 'shrink-0',
          fullWidth && 'w-full',
          className,
        )}
        {...rest}
      >
        {loading ? (
          <span
            className="h-3.5 w-3.5 animate-spin-slow rounded-full border-2 border-current border-t-transparent opacity-80"
            aria-hidden
          />
        ) : (
          icon
        )}
        {children}
      </button>
    )
  },
)

Button.displayName = 'Button'
