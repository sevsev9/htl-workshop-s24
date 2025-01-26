import { ChangeEvent, FormEvent, useState } from "react";
import type { User, UserDocument } from "@backend/model/user.model";

type UserResponse = Omit<User, "password"> & {
  _id: string;
};

export default function SignUpPage() {
  const [formValues, setFormValues] = useState<User>({
    username: "",
    email: "",
    password: "",
  });

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    try {
      const response = await fetch("http://localhost:8080/user", {
        method: "POST",
        body: JSON.stringify(formValues),
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

  const handleFormUpdate = (values: Partial<User>) => {
    setFormValues({
      ...formValues,
      ...values,
    });
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="border border-black p-5 flex flex-col"
    >
      <input
        value={formValues.username}
        onChange={(e) => handleFormUpdate({ username: e.target.value })}
        placeholder="username"
      />
      <input
        value={formValues.email}
        onChange={(e) => handleFormUpdate({ email: e.target.value })}
        placeholder="email"
      />
      <input
        value={formValues.password}
        onChange={(e) => handleFormUpdate({ password: e.target.value })}
        placeholder="password"
        type="password"
      />

      <button>Sign up</button>
    </form>
  );
}

