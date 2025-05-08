"use client";

import { useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import PasskeyManager from "@/components/passkey/PasskeyManager";
import { useTranslation } from "react-i18next";

type ManagePasskeysDialogProps = {
  show: boolean;
  onClose: () => void;
  username: string;
};

export default function ManagePasskeysDialog({
  show,
  onClose,
  username,
}: ManagePasskeysDialogProps) {
  const { t } = useTranslation(["components/passkey", "views/settings"]);

  // Reset state when dialog opens/closes
  useEffect(() => {
    if (show) {
      // Any initialization can go here
    }
  }, [show]);

  return (
    <Dialog open={show} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[600px] max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {t("titleForUser", { user: username })}
          </DialogTitle>
        </DialogHeader>

        <div className="py-2">
          <PasskeyManager forUser={username} />
        </div>
      </DialogContent>
    </Dialog>
  );
}