export const NODE = 'NODE';
export const BROWSER = 'BROWSER';

export class Helper {
    public static getRunningEnv(): string {
        if (typeof window === 'undefined') {
            return NODE;
        }
        return BROWSER;
    }
}

export interface StringMap {
    [key: string]: string;
}
