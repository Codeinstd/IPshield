const { validateTarget } = require("../utils/validateTarget");
const { exec } = require("child_process");
const util = require("util");
const execAsync = util.promisify(exec);

// Nmap scan
exports.runNmap = async (req, res) => {
  try {
    const { target } = req.body;

    const check = await validateTarget(target);
    if (!check.ok) {
      return res.status(400).json({ error: check.error });
    }

    const cmd = `nmap -sV -T4 ${target}`;
    const { stdout } = await execAsync(cmd);

    res.json({
      success: true,
      tool: "nmap",
      target,
      output: stdout
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// Nuclei scan
exports.runNuclei = async (req, res) => {
  try {
    const { target } = req.body;

    const check = await validateTarget(target); // ✅ IMPORTANT
    if (!check.ok) {
      return res.status(400).json({ error: check.error });
    }

    const cmd = `nuclei -u ${target} -silent`;
    const { stdout } = await execAsync(cmd);

    res.json({
      success: true,
      tool: "nuclei",
      target,
      output: stdout
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};