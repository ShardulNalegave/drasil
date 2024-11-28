import Navbar from '@/components/navbar';
import { ThemeProvider } from '@/components/theme-provider';
import { createRootRoute, Outlet } from '@tanstack/react-router';
import { TanStackRouterDevtools } from '@tanstack/router-devtools';

export const Route = createRootRoute({
  component: Root,
})

function Root() {
  return (
    <ThemeProvider defaultTheme='dark'>
      <Navbar />
      <Outlet />
      <TanStackRouterDevtools />
    </ThemeProvider>
  );
}