const { spawn } = require("child_process");

function runNmap(target) {
  return new Promise((resolve, reject) => {
    let output = "";

    const scan = spawn("nmap", [
      "-sV",
      "-oX",
      "-",
      target
    ]);

    scan.stdout.on("data", data => {
      output += data.toString();
    });

    scan.stderr.on("data", data => {
      console.error(data.toString());
    });

    scan.on("close", code => {
      if (code !== 0) {
        return reject(new Error("Nmap scan failed"));
      }

      resolve(output);
    });
  });
}

module.exports = { runNmap };