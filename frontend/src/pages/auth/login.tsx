import { FormEvent, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { User } from "@backend/model/user.model";
import { AuthLayout } from "@/layouts/AuthLayout";
import HomeLayout from "@/layouts/HomeLayout";

// todo improve type
type LoginProps = Pick<User, "email" | "password">;

export default function LoginPage() {
  const handleSubmit = async (user: LoginProps) => {
    try {
      // todo implement login logic
    } catch (e) {
      // todo show toast on error (add sonner component)
      console.log(e);
    }
  };

  return <LoginForm onSubmit={handleSubmit} />;
}

const LoginForm = ({ onSubmit }: { onSubmit: (user: LoginProps) => void }) => {
  const [formValues, setFormValues] = useState<LoginProps>({
    email: "",
    password: "",
  });

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    // todo maybe error handling?
    onSubmit(formValues);
  };

  const handleFormUpdate = (values: Partial<User>) => {
    setFormValues({
      ...formValues,
      ...values,
    });
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="border-black p-5 flex flex-col max-w-sm gap-2 w-full"
    >
      <Input
        value={formValues.email}
        onChange={(e) => handleFormUpdate({ email: e.target.value })}
        placeholder="email"
      />
      <Input
        value={formValues.password}
        onChange={(e) => handleFormUpdate({ password: e.target.value })}
        placeholder="password"
        type="password"
      />

      <Button>Login</Button>
    </form>
  );
};

LoginPage.getLayout = (page: React.ReactElement) => {
  return (
    <HomeLayout>
      <AuthLayout
        header={{
          title: "Welcome back",
          description: "Enter your credentials to login",
        }}
        link={{
          text: "You don't have an account? Sign up",
          href: "/auth/sign-up",
        }}
      >
        {page}
      </AuthLayout>
    </HomeLayout>
  );
};
