import { cn } from "../../lib/utils";
import PropTypes from "prop-types";

function Select({ className, children, ...props }) {
  return (
    <select
      className={cn(
        "flex h-9 w-full rounded-md border border-slate-300 bg-white px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-500 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    >
      {children}
    </select>
  );
}

export { Select };

Select.propTypes = {
  className: PropTypes.string,
  children: PropTypes.node,
};
