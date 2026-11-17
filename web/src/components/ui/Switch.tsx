import { forwardRef, useId, useState, type ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface SwitchBaseProps {
  checked?: boolean
  defaultChecked?: boolean
  onCheckedChange?: (checked: boolean) => void
  disabled?: boolean
  label?: ReactNode
  description?: ReactNode
  size?: 'sm' | 'md'
  className?: string
  id?: string
  /**
   * Accessible name for a standalone switch (table rows, toolbars) where a
   * visible `label` would break the layout. Required when `label` is absent.
   */
  ariaLabel?: string
  /**
   * DOM spelling of {@link SwitchBaseProps.ariaLabel}, accepted so existing
   * call sites (which used to pass a prop the component silently dropped) keep
   * working. Prefer `ariaLabel` in new code.
   */
  'aria-label'?: string
}

/**
 * A switch always needs an accessible name: either the visible `label`
 * (rendered as `<label htmlFor>` so clicking the text toggles it), or
 * `ariaLabel` for standalone switches. Omitting both is a type error, which is
 * what keeps axe `button-name` / `aria-toggle-field-name` at zero.
 */
export type SwitchProps = SwitchBaseProps &
  (
    | { label: ReactNode }
    | { label?: undefined; ariaLabel: string }
    | { label?: undefined; 'aria-label': string }
  )

export const Switch = forwardRef<HTMLButtonElement, SwitchProps>(
  (
    props,
    ref,
  ) => {
    const {
      checked,
      defaultChecked = false,
      onCheckedChange,
      disabled = false,
      label,
      description,
      size = 'md',
      className,
      id,
      ariaLabel,
      'aria-label': ariaLabelProp,
    } = props as SwitchBaseProps
    const generatedId = useId()
    const switchId = id ?? generatedId
    const descriptionId = `${switchId}-description`
    const accessibleName = ariaLabel ?? ariaLabelProp
    const isControlled = checked !== undefined
    const [internal, setInternal] = useState(defaultChecked)
    const isOn = isControlled ? checked : internal

    const dims =
      size === 'sm'
        ? { track: 'h-5 w-9', thumb: 'h-4 w-4', translate: 'translate-x-4' }
        : { track: 'h-6 w-11', thumb: 'h-5 w-5', translate: 'translate-x-5' }

    const toggle = () => {
      if (disabled) return
      const next = !isOn
      if (!isControlled) setInternal(next)
      onCheckedChange?.(next)
    }

    const control = (
      <button
        ref={ref}
        id={switchId}
        type="button"
        role="switch"
        aria-checked={isOn}
        aria-label={accessibleName}
        aria-describedby={description ? descriptionId : undefined}
        disabled={disabled}
        onClick={toggle}
        className={cn(
          'relative inline-flex shrink-0 items-center rounded-full border transition-colors duration-200',
          dims.track,
          isOn ? 'border-transparent bg-brand' : 'border-line bg-fill',
          disabled && 'cursor-not-allowed opacity-50',
        )}
      >
        <span
          className={cn(
            'pointer-events-none absolute left-0.5 inline-block rounded-full bg-white shadow-sm transition-transform duration-200',
            dims.thumb,
            isOn ? dims.translate : 'translate-x-0',
          )}
        />
      </button>
    )

    if (!label && !description) {
      return <span className={className}>{control}</span>
    }

    return (
      <div className={cn('flex items-start gap-3', className)}>
        {control}
        <label
          htmlFor={switchId}
          className="flex cursor-pointer flex-col pt-0.5 leading-tight"
        >
          {label && <span className="text-sm font-medium text-fg">{label}</span>}
          {description && (
            <span id={descriptionId} className="mt-0.5 text-xs text-fg-subtle">
              {description}
            </span>
          )}
        </label>
      </div>
    )
  },
)

Switch.displayName = 'Switch'
