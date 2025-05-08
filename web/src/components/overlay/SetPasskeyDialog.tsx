import React, { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { startRegistration } from "@simplewebauthn/browser";

interface SetPasskeyDialogProps {
  show: boolean;
  onCancel: () => void;
  onSave: (passkey: string) => void;
}

const SetPasskeyDialog: React.FC<SetPasskeyDialogProps> = ({ show, onCancel, onSave }) => {
  // The passkey state is unused since the WebAuthn API handles the key generation
  const [isLoading, setIsLoading] = useState(false);

  const handleRegisterPasskey = async () => {
    setIsLoading(true);
    try {
      // Fetch registration options from the backend
      const optionsResponse = await fetch("/api/webauthn/registration-options");
      if (!optionsResponse.ok) {
        throw new Error("Failed to fetch registration options");
      }
      const options = await optionsResponse.json();

      // Start WebAuthn registration
      const credential = await startRegistration(options);

      // Send the credential to the backend for storage
      const registerResponse = await fetch("/api/webauthn/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-TOKEN": "1"
        },
        body: JSON.stringify(credential),
      });

      if (!registerResponse.ok) {
        throw new Error("Failed to register passkey");
      }

      // Call onSave with a placeholder since we don't need an actual passkey string
      // The server generates and stores the actual credential
      onSave("passkey-registered");
      toast.success("Passkey registered successfully");
      onCancel();
    } catch (error: unknown) {
      let errorMessage = "Failed to register passkey";
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      toast.error(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={show} onOpenChange={onCancel}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Register Passkey</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <Button onClick={handleRegisterPasskey} disabled={isLoading} className="w-full">
            {isLoading ? "Registering..." : "Register Passkey"}
          </Button>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={isLoading}>
            Cancel
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default SetPasskeyDialog;