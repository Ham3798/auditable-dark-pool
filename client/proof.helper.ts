import fs from "fs";
import path from "path";
import { execSync } from "child_process";

// New input structure for BabyJubJub-based shielded pool
export interface ShieldedPoolInputs {
    // Public inputs
    root: string;
    nullifier: string;
    recipient: string;
    amount: number | string;
    wa_commitment: string;  // NEW: auditable identity commitment
    
    // Private inputs
    secret_key: string;     // NEW: renamed from 'secret'
    owner_x: string;        // NEW: public key x coordinate
    owner_y: string;        // NEW: public key y coordinate
    randomness: string;     // NEW: commitment randomness
    index: number | string;
    siblings: string[];
}

export interface CircuitConfig {
    circuitDir: string;
    circuitName: string;
}

export function generateProof(config: CircuitConfig, inputs: ShieldedPoolInputs) {
    const proverTomlPath = path.join(config.circuitDir, "Prover.toml");

    // Format TOML with new input structure
    let toml = "";
    // Public inputs
    toml += `root = "${inputs.root}"\n`;
    toml += `nullifier = "${inputs.nullifier}"\n`;
    toml += `recipient = "${inputs.recipient}"\n`;
    toml += `amount = ${inputs.amount}\n`;
    toml += `wa_commitment = "${inputs.wa_commitment}"\n`;
    
    // Private inputs
    toml += `secret_key = "${inputs.secret_key}"\n`;
    toml += `owner_x = "${inputs.owner_x}"\n`;
    toml += `owner_y = "${inputs.owner_y}"\n`;
    toml += `randomness = "${inputs.randomness}"\n`;
    toml += `index = ${inputs.index}\n`;
    toml += `siblings = [\n`;
    for (const sib of inputs.siblings) {
        toml += `  "${sib}",\n`;
    }
    toml += `]\n`;

    fs.writeFileSync(proverTomlPath, toml);

    // Run nargo execute
    execSync("nargo execute", { cwd: config.circuitDir });

    // Run sunspot prove
    const targetDir = path.join(config.circuitDir, "target");
    const acirPath = path.join(targetDir, `${config.circuitName}.json`);
    const witnessPath = path.join(targetDir, `${config.circuitName}.gz`);
    const ccsPath = path.join(targetDir, `${config.circuitName}.ccs`);
    const pkPath = path.join(targetDir, `${config.circuitName}.pk`);

    execSync(`sunspot prove ${acirPath} ${witnessPath} ${ccsPath} ${pkPath}`, {
        cwd: config.circuitDir,
    });

    const proof = fs.readFileSync(path.join(targetDir, `${config.circuitName}.proof`));
    const publicWitness = fs.readFileSync(path.join(targetDir, `${config.circuitName}.pw`));

    return { proof, publicWitness };
}
