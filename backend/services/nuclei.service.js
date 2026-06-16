const { spawn } = require("child_process");

function runNuclei(target) {
  return new Promise((resolve, reject) => {
    let output = "";

    const scan = spawn("nuclei", [
      "-u",
      target,
      "-json"
    ]);

    scan.stdout.on("data", data => {
      output += data.toString();
    });

    scan.on("close", code => {
      if (code !== 0) {
        return reject(new Error("Nuclei scan failed"));
      }

      resolve(output);
    });
  });
}

module.exports = { runNuclei };