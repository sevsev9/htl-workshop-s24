import AuthProvider from "@/context/AuthContext";
import { AppPropsWithLayout } from "@/types/next";
import "@/styles/globals.css";

export default function App({ Component, pageProps }: AppPropsWithLayout) {
  const getLayout = Component.getLayout ?? ((page: React.ReactElement) => page);

  const renderComponent = () => {
    return getLayout(<Component {...pageProps} />);
  };

  return (
    <AuthProvider>
      {renderComponent()}
      {/* <Toaster /> */}
    </AuthProvider>
  );
}
