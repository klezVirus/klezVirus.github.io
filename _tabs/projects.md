---
icon: fas fa-diagram-project
order: 4
---

Here are some of the tools, PoCs, and experiments I’ve shared over the years — mostly related to Windows internals, EDR evasion, offensive security, and a bit of Python and C# glue to make life easier during red team ops.  
I’m a big believer in free and open-source software, so if something here is helpful, feel free to contribute, fork, or just reach out.


<style>
.project-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.5rem;
  margin-top: 2rem;
}

.project-card {
  background: #1f1f1f;
  padding: 1rem;
  border-radius: 8px;
  color: #ddd;
  text-decoration: none;
  box-shadow: 0 2px 6px rgba(0,0,0,0.3);
  transition: transform 0.2s ease;
  display: block;
}

.project-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.4);
}

.project-icon {
  font-size: 2rem;
  margin-bottom: 0.4rem;
}

.project-card h3 {
  margin: 0.2rem 0;
  color: #fff;
  font-size: 1.2rem;
}

.project-card p {
  font-size: 0.95rem;
  color: #ccc;
  margin: 0.4rem 0 0;
}
</style>

<div class="project-grid">

  <a href="https://github.com/klezVirus/SilentMoonwalk" class="project-card" target="_blank">
    <div class="project-icon">🌒</div>
    <h3>SilentMoonwalk</h3>
    <p>PoC for building a fully dynamic call stack spoofer on Windows x64. Spoofs call origin at runtime.</p>
  </a>

  <a href="https://github.com/klezVirus/inceptor" class="project-card" target="_blank">
    <div class="project-icon">🎯</div>
    <h3>inceptor</h3>
    <p>Template-driven AV/EDR evasion framework built in Assembly and C/C++ with modular capabilities.</p>
  </a>

  <a href="https://github.com/klezVirus/SysWhispers3" class="project-card" target="_blank">
    <div class="project-icon">🧬</div>
    <h3>SysWhispers3</h3>
    <p>“SysWhispers on steroids”—direct syscalls & injection avoidance, especially for WoW64 & x64 systems.</p>
  </a>

  <a href="https://github.com/klezVirus/chameleon" class="project-card" target="_blank">
    <div class="project-icon">🦎</div>
    <h3>chameleon</h3>
    <p>Python-based PowerShell obfuscator for payload delivery and stealth scenarios.</p>
  </a>

  <a href="https://github.com/klezVirus/vortex" class="project-card" target="_blank">
    <div class="project-icon">🌀</div>
    <h3>vortex</h3>
    <p>Full-stack VPN reconnaissance & exploitation toolkit—active reconnaissance made easier.</p>
  </a>

  <a href="https://github.com/klezVirus/CheeseTools" class="project-card" target="_blank">
    <div class="project-icon">🧀</div>
    <h3>CheeseTools</h3>
    <p>C#/PowerShell tools for lateral movement and code execution automation in red team ops.</p>
  </a>

</div>
