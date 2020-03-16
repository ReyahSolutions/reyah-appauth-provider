import process from 'process';
import { LocalStorage as NodeLocalStorage } from 'node-localstorage';
import { Helper, BROWSER } from './helper';

export class LocalStorage implements Storage {
    private localStorage: Storage;

    constructor() {
        if (Helper.getRunningEnv() === BROWSER) {
            this.localStorage = window.localStorage;
        } else {
            this.localStorage = new NodeLocalStorage(process.env.AUTH_STORAGE_PATH || './credentials');
        }
    }

    get length(): number {
        return this.localStorage.length;
    }

    clear(): void {
        this.localStorage.clear();
    }
    getItem(key: string): string | null {
        return this.localStorage.getItem(key);
    }
    key(index: number): string | null {
        return this.localStorage.key(index);
    }
    removeItem(key: string): void {
        this.localStorage.removeItem(key);
    }
    setItem(key: string, value: string): void {
        this.localStorage.setItem(key, value);
    }
}

export default LocalStorage;
