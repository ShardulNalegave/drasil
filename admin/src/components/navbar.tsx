import { ThemeToggle } from "./theme-provider";

export default function Navbar() {
  return (
    <div className='p-[15px] sticky border-solid border-b-[1px] border-zinc-200 dark:border-zinc-900 flex items-center'>
      <div>
        <h1 className='font-heading font-bold text-lg'>Drasil</h1>
      </div>
      <div className='grow'></div>
      <ThemeToggle />
    </div>
  );
}