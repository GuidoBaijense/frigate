import { forwardRef } from "react";
import { IconType } from "react-icons";

interface IconWrapperProps {
  icon: IconType;
  className?: string;
  [key: string]: any;
}

const IconWrapper = forwardRef<HTMLDivElement, IconWrapperProps>(
  ({ icon: Icon, className, ...props }, ref) => (
    <div {...props} ref={ref}>
      <Icon className={className} />
    </div>
  )
);

// Add display name for better debugging
IconWrapper.displayName = "IconWrapper";

export default IconWrapper;
