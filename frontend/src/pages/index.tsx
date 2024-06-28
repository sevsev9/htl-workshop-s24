import { useState } from "react";

const useIndexPage = () => {
  const [foo, setFoo] = useState("Hello world")

  const handleChange = (value: string) => {
// validation

    setFoo(value)
  }

  return {
    foo,
    handleChange
  }
};

export default function Home() {
  const { foo, handleChange } = useIndexPage() 
  
  return (
    <main>
    </main>
  );
}
