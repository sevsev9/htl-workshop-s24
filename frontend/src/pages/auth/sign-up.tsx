import { FormEvent, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AuthLayout } from "@/layouts/AuthLayout";
import HomeLayout from "@/layouts/HomeLayout";
import type { User } from "@backend/model/user.model";

type UserResponse = Omit<User, "password"> & {
  _id: string;
};

export default function SignUpPage() {
  const handleSubmit = async (newUser: User) => {
    try {
      const response = await fetch("http://localhost:8080/user", {
        method: "POST",
        body: JSON.stringify(newUser),
        headers: {
          "Content-Type": "application/json",
        },
      });

      const data = (await response.json()) as UserResponse;

      if (!response.ok) {
        throw new Error("nope");
      }

      console.log(data);
    } catch (e) {
      console.log(e);
    }
  };

  return <SignUpForm onSubmit={handleSubmit} />;
}

const SignUpForm = ({ onSubmit }: { onSubmit: (user: User) => void }) => {
  const [formValues, setFormValues] = useState<User>({
    username: "",
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
    <form onSubmit={handleSubmit} className="flex flex-col gap-2">
      <Input
        value={formValues.username}
        onChange={(e) => handleFormUpdate({ username: e.target.value })}
        placeholder="username"
      />
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

      <Button>Sign up</Button>
    </form>
  );
};

SignUpPage.getLayout = (page: React.ReactElement) => {
  return (
    <HomeLayout>
      <AuthLayout
        header={{
          title: "Welcome",
          description: "Create a new account",
        }}
        link={{
          text: "You already have an account? Login",
          href: "/auth/login",
        }}
      >
        {page}
      </AuthLayout>
    </HomeLayout>
  );
};
