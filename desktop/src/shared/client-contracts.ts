export interface ClientInventoryIdentity {
    readonly buildCode: number;
    readonly appVersion: number;
    readonly channel: number;
    readonly versionName: string;
}

export interface ClientInventoryFile {
    readonly path: string;
    readonly size: number;
    readonly sha256: string;
}

export interface ClientAssetHashCandidate extends ClientInventoryFile {
    readonly md5: string;
    readonly identity: ClientInventoryIdentity;
    readonly filenameAppVersion: number;
    readonly filenameBuildCode: number;
    readonly identityMatch: boolean;
    readonly canonicalMatch: boolean;
}

export interface ClientInventory {
    readonly root: string;
    readonly state: 'observed';
    readonly gate: 'G0';
    readonly businessReady: false;
    readonly identity: ClientInventoryIdentity;
    readonly index: ClientInventoryFile & {
        readonly entryCount: number;
        readonly scriptsLogicalName: 'scripts64' | 'scripts64.ys';
    };
    readonly keyFiles: readonly ClientInventoryFile[];
    readonly scripts: ClientInventoryFile & {
        readonly logicalName: 'scripts64' | 'scripts64.ys';
        readonly expectedMd5: string;
        readonly md5: string;
    };
    readonly indexCandidates: readonly ClientAssetHashCandidate[];
    readonly issues: readonly string[];
    readonly limitations: readonly string[];
}
