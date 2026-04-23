import { cn } from "../../lib/utils";
import PropTypes from "prop-types";

function Checkbox({ className, ...props }) {
  return <input type="checkbox" className={cn("h-4 w-4 rounded border-slate-300 text-slate-900", className)} {...props} />;
}

export { Checkbox };

Checkbox.propTypes = {
  className: PropTypes.string,
};
