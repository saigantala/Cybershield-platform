"use client";

import { useState } from "react";
import { Sidebar } from "./Sidebar";
import { Navbar } from "./Navbar";

interface DashboardLayoutProps {
  children: React.ReactNode;
}

export function DashboardLayout({ children }: DashboardLayoutProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[#080D18]">
      {/* Sidebar with desktop collapsing and mobile drawer */}
      <Sidebar
        isCollapsed={isCollapsed}
        setIsCollapsed={setIsCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar onToggleMobileMenu={() => setMobileOpen(true)} />
        <main className="flex-1 p-4 sm:p-6 md:p-8 soc-grid-bg overflow-y-auto">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
