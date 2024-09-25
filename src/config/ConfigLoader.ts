import fs from "fs";
import { load } from "js-yaml";
import path from "path";
import { FSWatcher } from "./types";
import { EventEmitter } from "stream";

// Generic ConfigLoader class
class ConfigLoader<T> extends EventEmitter {
  private config: T | null = null;
  private configPath: string | null = null;
  private watchFunction: FSWatcher;

  constructor(relativePath: string, watchFunction: FSWatcher) {
    super();
    this.watchFunction = watchFunction;
    this.setConfigPath(relativePath);
    this.loadConfig();
    this.watchConfig();
  }

  private setConfigPath(relativePath: string) {
    const filePath = path.join(__dirname, relativePath);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Configuration file not found: ${filePath}`);
    }
    this.configPath = filePath;
  }

  // Load the configuration from file
  private loadConfig() {
    if (!this.configPath) {
      throw new Error("Configuration path not set");
    }
    const configContent = fs.readFileSync(this.configPath, "utf-8");
    this.config = load(configContent) as T;
  }

  // Watch for file changes
  private async watchConfig() {
    if (!this.configPath) {
      throw new Error("Configuration path not set");
    }
    const watcher = this.watchFunction(this.configPath);
    for await (const event of watcher) {
      if (event.eventType === "change") {
        console.log(`${this.configPath} changed, reloading configuration...`);

        this.emit("configChange", this.config);
        this.loadConfig();
      }
    }
  }

  // Get the current configuration
  public getConfig(): T {
    if (!this.config) {
      throw new Error("Configuration not loaded");
    }
    return this.config;
  }
}

export default ConfigLoader;
