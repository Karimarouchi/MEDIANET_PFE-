import React from 'react';

const Dashboard: React.FC = () => {
  return (
    <>
      {/* Hero Welcome */}
      <div className="mb-10 flex flex-col md:flex-row md:items-end justify-between gap-6">
        <div>
          <h1 className="font-headline text-4xl font-extrabold tracking-tighter text-on-surface">Welcome back, Commander.</h1>
          <div className="flex items-center gap-2 mt-2">
            <span className="flex h-2 w-2 rounded-full bg-tertiary pulse-secure"></span>
            <p className="text-sm text-outline font-medium">
              System status: <span className="text-tertiary font-bold tracking-widest uppercase">SECURE</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 bg-surface-container-low p-1.5 rounded-xl border border-outline-variant/[0.1]">
          <button className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-outline hover:text-on-surface transition-colors">Day</button>
          <button className="px-4 py-2 text-xs font-bold uppercase tracking-wider text-outline hover:text-on-surface transition-colors">Week</button>
          <button className="px-4 py-2 text-xs font-bold uppercase tracking-wider bg-surface-container-highest text-primary rounded-lg shadow-sm">Month</button>
        </div>
      </div>

      {/* Overview Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Card: Total Vulnerabilities */}
        <div className="glass-panel p-6 rounded-xl border border-outline-variant/[0.1] group hover:border-primary/[0.3] transition-all duration-500 overflow-hidden relative">
          <div className="absolute -right-8 -top-8 w-32 h-32 bg-primary/5 blur-3xl rounded-full transition-all group-hover:bg-primary/20"></div>
          <div className="flex justify-between items-start mb-4">
            <span className="text-outline text-xs font-bold uppercase tracking-widest font-label">Total Vulnerabilities</span>
            <span className="material-symbols-outlined text-primary">bug_report</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-5xl font-headline font-bold text-on-surface glow-text-primary">124</span>
            <span className="text-tertiary text-xs font-medium flex items-center gap-1">
              <span className="material-symbols-outlined text-[14px]">trending_down</span> 12%
            </span>
          </div>
          <div className="mt-4 flex gap-1 h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
            <div className="w-[10%] bg-error"></div>
            <div className="w-[20%] bg-secondary"></div>
            <div className="w-[35%] bg-primary"></div>
            <div className="w-[35%] bg-outline"></div>
          </div>
        </div>

        {/* Card: Severity Breakdown */}
        <div className="glass-panel p-6 rounded-xl border border-outline-variant/[0.1] group hover:border-secondary/[0.3] transition-all duration-500">
          <span className="text-outline text-xs font-bold uppercase tracking-widest font-label block mb-6">Severity Breakdown</span>
          <div className="grid grid-cols-2 gap-4">
            <div className="flex flex-col">
              <span className="text-[10px] text-outline font-bold uppercase tracking-tighter mb-1">Critical</span>
              <span className="text-xl font-headline font-bold text-error">03</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] text-outline font-bold uppercase tracking-tighter mb-1">High</span>
              <span className="text-xl font-headline font-bold text-secondary">12</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] text-outline font-bold uppercase tracking-tighter mb-1">Medium</span>
              <span className="text-xl font-headline font-bold text-primary">45</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[10px] text-outline font-bold uppercase tracking-tighter mb-1">Low</span>
              <span className="text-xl font-headline font-bold text-on-surface-variant">64</span>
            </div>
          </div>
        </div>

        {/* Card: Security Score */}
        <div className="glass-panel p-6 rounded-xl border border-outline-variant/[0.1] group hover:border-tertiary/[0.3] transition-all duration-500 flex items-center justify-between">
          <div>
            <span className="text-outline text-xs font-bold uppercase tracking-widest font-label block mb-1">Security Score</span>
            <p className="text-[10px] text-outline-variant max-w-[120px]">Calculated via real-time CVSS telemetry.</p>
            <div className="mt-4">
              <span className="text-3xl font-headline font-bold text-tertiary">8.4</span>
              <span className="text-outline text-lg font-headline">/10</span>
            </div>
          </div>
          <div className="relative w-24 h-24">
            <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
              <circle className="stroke-surface-container-highest" cx="18" cy="18" fill="none" r="16" strokeWidth="3"></circle>
              <circle className="stroke-tertiary" cx="18" cy="18" fill="none" r="16" strokeDasharray="84, 100" strokeLinecap="round" strokeWidth="3"></circle>
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="material-symbols-outlined text-tertiary text-2xl" style={{ fontVariationSettings: "'FILL' 1" }}>verified</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Dashboard Charts & Lists */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Trends */}
        <div className="lg:col-span-2 glass-panel p-8 rounded-xl border border-outline-variant/[0.1] min-h-[400px] flex flex-col">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h3 className="font-headline text-xl font-bold text-on-surface">Security Trends</h3>
              <p className="text-sm text-outline">Incident velocity &amp; mitigation rate (last 30 days)</p>
            </div>
            <button className="text-slate-400 hover:text-on-surface">
              <span className="material-symbols-outlined">more_vert</span>
            </button>
          </div>
          <div className="flex-1 flex flex-col justify-end gap-1">
            <div className="relative w-full h-full mt-4 bg-gradient-to-t from-primary/5 to-transparent rounded-lg flex items-end">
              <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 400 150">
                <path className="stroke-primary" d="M0,120 Q50,110 100,130 T200,90 T300,110 T400,60" fill="none" strokeWidth="2.5"></path>
                <path className="stroke-secondary" d="M0,140 Q50,135 100,145 T200,120 T300,135 T400,100" fill="none" strokeDasharray="4" strokeWidth="2"></path>
              </svg>
              <div className="absolute inset-0 grid grid-rows-4 w-full h-full pointer-events-none">
                <div className="border-t border-outline-variant/5"></div>
                <div className="border-t border-outline-variant/5"></div>
                <div className="border-t border-outline-variant/5"></div>
                <div className="border-t border-outline-variant/5"></div>
              </div>
            </div>
            <div className="flex justify-between px-2 text-[10px] text-outline font-bold uppercase tracking-wider mt-4">
              <span>01 Oct</span><span>08 Oct</span><span>15 Oct</span><span>22 Oct</span><span>30 Oct</span>
            </div>
          </div>
        </div>

        {/* Vulnerability Types */}
        <div className="glass-panel p-8 rounded-xl border border-outline-variant/[0.1] flex flex-col">
          <h3 className="font-headline text-xl font-bold text-on-surface mb-8">Vulnerability Types</h3>
          <div className="flex-1 flex flex-col items-center justify-center">
            <div className="relative w-48 h-48 rounded-full border-[16px] border-surface-container-highest flex items-center justify-center mb-8">
              <div className="absolute inset-0 rounded-full border-[16px] border-t-primary border-r-secondary border-b-error border-l-transparent -rotate-45"></div>
              <div className="text-center">
                <span className="block text-2xl font-bold font-headline">78%</span>
                <span className="text-[10px] text-outline uppercase tracking-widest">Network</span>
              </div>
            </div>
            <div className="w-full space-y-4">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-primary"></span>
                  <span className="text-on-surface-variant">XSS Injection</span>
                </div>
                <span className="font-bold text-on-surface">42%</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-secondary"></span>
                  <span className="text-on-surface-variant">SQL Logic</span>
                </div>
                <span className="font-bold text-on-surface">28%</span>
              </div>
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-error"></span>
                  <span className="text-on-surface-variant">Auth Bypass</span>
                </div>
                <span className="font-bold text-on-surface">15%</span>
              </div>
            </div>
          </div>
        </div>

        {/* System Activity Timeline */}
        <div className="lg:col-span-3 glass-panel p-8 rounded-xl border border-outline-variant/[0.1] mt-2">
          <div className="flex justify-between items-center mb-6">
            <h3 className="font-headline text-xl font-bold text-on-surface">System Activity Timeline</h3>
            <button className="text-xs font-bold text-primary uppercase tracking-widest hover:underline">View All Logs</button>
          </div>
          <div className="space-y-0 relative">
            <div className="absolute left-[19px] top-4 bottom-4 w-px bg-outline-variant/[0.2]"></div>

            {/* Timeline Item 1 */}
            <div className="relative flex items-center gap-6 py-4 px-2 hover:bg-surface-container/40 rounded-lg transition-colors group">
              <div className="z-10 w-8 h-8 rounded-full bg-surface-container border-2 border-tertiary flex items-center justify-center">
                <span className="material-symbols-outlined text-tertiary text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>check_circle</span>
              </div>
              <div className="flex-1 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-on-surface">Core Banking Engine - Scan Complete</p>
                  <p className="text-xs text-outline">Target: production-v4.0.2 • Completed 4 mins ago</p>
                </div>
                <span className="px-3 py-1 bg-tertiary-container/10 text-tertiary text-[10px] font-bold uppercase rounded border border-tertiary/[0.2]">Success</span>
              </div>
            </div>

            {/* Timeline Item 2 */}
            <div className="relative flex items-center gap-6 py-4 px-2 hover:bg-surface-container/40 rounded-lg transition-colors group">
              <div className="z-10 w-8 h-8 rounded-full bg-surface-container border-2 border-secondary flex items-center justify-center animate-pulse">
                <span className="material-symbols-outlined text-secondary text-lg">sync</span>
              </div>
              <div className="flex-1 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-on-surface">Neural Gateway Middleware - Deep Analysis</p>
                  <p className="text-xs text-outline">Analyzing 4,821 modules... • 82% complete</p>
                </div>
                <span className="px-3 py-1 bg-secondary-container/10 text-secondary text-[10px] font-bold uppercase rounded border border-secondary/[0.2]">In Progress</span>
              </div>
            </div>

            {/* Timeline Item 3 */}
            <div className="relative flex items-center gap-6 py-4 px-2 hover:bg-surface-container/40 rounded-lg transition-colors group">
              <div className="z-10 w-8 h-8 rounded-full bg-surface-container border-2 border-error flex items-center justify-center">
                <span className="material-symbols-outlined text-error text-lg" style={{ fontVariationSettings: "'FILL' 1" }}>warning</span>
              </div>
              <div className="flex-1 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-on-surface">Legacy Auth Wrapper - Policy Violation</p>
                  <p className="text-xs text-outline">High risk vulnerability detected in submodule `crypto-js` • 1 hour ago</p>
                </div>
                <span className="px-3 py-1 bg-error-container/10 text-error text-[10px] font-bold uppercase rounded border border-error/[0.2]">Warning</span>
              </div>
            </div>

            {/* Timeline Item 4 */}
            <div className="relative flex items-center gap-6 py-4 px-2 hover:bg-surface-container/40 rounded-lg transition-colors group">
              <div className="z-10 w-8 h-8 rounded-full bg-surface-container border-2 border-outline-variant flex items-center justify-center">
                <span className="material-symbols-outlined text-outline text-lg">history</span>
              </div>
              <div className="flex-1 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-on-surface">Node.js API Microservice - Nightly Build</p>
                  <p className="text-xs text-outline">Scheduled scan pending • 4 hours ago</p>
                </div>
                <span className="px-3 py-1 bg-surface-container-high text-outline text-[10px] font-bold uppercase rounded border border-outline-variant/[0.3]">Pending</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Dashboard;
