import { cn } from "../../lib/utils";
import PropTypes from "prop-types";

function Card({ className, ...props }) {
  return <div className={cn("rounded-xl border border-slate-200 bg-white shadow-sm", className)} {...props} />;
}

function CardHeader({ className, ...props }) {
  return <div className={cn("flex flex-col space-y-1.5 p-5", className)} {...props} />;
}

function CardTitle({ className, ...props }) {
  return <h3 className={cn("text-base font-semibold leading-none tracking-tight", className)} {...props} />;
}

function CardDescription({ className, ...props }) {
  return <p className={cn("text-sm text-slate-500", className)} {...props} />;
}

function CardContent({ className, ...props }) {
  return <div className={cn("p-5 pt-0", className)} {...props} />;
}

export { Card, CardHeader, CardTitle, CardDescription, CardContent };

Card.propTypes = { className: PropTypes.string };
CardHeader.propTypes = { className: PropTypes.string };
CardTitle.propTypes = { className: PropTypes.string };
CardDescription.propTypes = { className: PropTypes.string };
CardContent.propTypes = { className: PropTypes.string };
