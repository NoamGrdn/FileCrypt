import React, {useState, useCallback, useMemo, memo, useEffect} from 'react';
import ReactDOM from 'react-dom/client'
import {Play, Square, RotateCcw, Monitor, Smartphone, Workflow, ChartNetwork} from 'lucide-react';
import mermaid from "mermaid";


const SequenceDiagram = memo(() => {
    let currentZoom = 1;
    let currentInfo = null;

    // Initialize Mermaid
    mermaid.initialize({
        startOnLoad: false,
        theme: 'default',
        securityLevel: 'loose',
        sequence: {
            diagramMarginX: 50,
            diagramMarginY: 10,
            actorMargin: 50,
            width: 150,
            height: 65,
            boxMargin: 10,
            boxTextMargin: 5,
            noteMargin: 10,
            messageMargin: 35
        }
    });

    // Mermaid diagram definition
    const diagramDefinition = useMemo(() =>`
sequenceDiagram
    participant App as 📱 Application
    participant FM as 🔧 Filter Manager
    participant FC as 🔐 FileCrypt Driver
    participant StSec as 🛡️ Security Module
    participant TPM as 🔑 TPM/Registry
    participant FS as 💾 File System

    Note over FC: 🚀 Driver Initialization
    FC->>TPM: Initialize master key (StSecpGetMasterKey)
    TPM-->>FC: Sealed/Unsealed master key
    FC->>TPM: Load security policies from registry
    TPM-->>FC: Security descriptors & folder properties
    FC->>FM: Register filter callbacks

    Note over App,FS: 📄 File Creation Flow
    App->>FM: CreateFile("\\\\Documents\\\\MyApp\\\\file.txt")
    FM->>FC: FCPreCreate()
    
    FC->>FC: Parse file path & construct full path
    FC->>StSec: StSecGetSecurityDescriptor(path)
    StSec->>StSec: Find matching security policy
    StSec->>StSec: Determine chamber ID (e.g., "MyAppChamber")
    StSec-->>FC: Security descriptor + chamber info
    
    FC->>FC: FCpAccessCheck() with security descriptor
    alt Access Denied
        FC->>FC: Modify create disposition if possible
    end
    
    FC->>FS: Forward create request
    FS-->>FC: File handle created
    
    FC->>FC: FCPostCreate()
    FC->>StSec: StSecpDeriveChamberProfileKey(chamber_id)
    StSec->>TPM: Get/derive encryption key for chamber
    TPM-->>StSec: Chamber-specific encryption key
    StSec-->>FC: Key data
    FC->>FC: Create stream context with encryption key
    FC-->>FM: Success
    FM-->>App: File handle

    Note over App,FS: ✍️ File Write Flow
    App->>FM: WriteFile(data)
    FM->>FC: FCPreWrite()
    
    FC->>FC: Get stream context (encryption keys)
    FC->>FC: Get volume context (sector size, etc.)
    FC->>FC: Allocate shadow buffer for encrypted data
    FC->>FC: FCpEncEncrypt() - Encrypt data with AES-CBC
    FC->>FC: Replace original buffer with encrypted buffer
    FC->>FS: Forward encrypted write
    FS-->>FC: Write complete
    
    FC->>FC: FCPostWrite() - Cleanup buffers
    FC-->>FM: Success
    FM-->>App: Write complete

    Note over App,FS: 📖 File Read Flow
    App->>FM: ReadFile()
    FM->>FC: FCPreRead()
    
    FC->>FC: Get stream context (check if encrypted)
    alt File is encrypted
        FC->>FC: Get volume context
        FC->>FC: Set up completion context
        FC->>FS: Forward read request
        FS-->>FC: Encrypted data read
        
        FC->>FC: FCPostRead()
        alt High IRQL or Large Read
            FC->>FC: Queue FCDecryptWorker() asynchronously
        else
            FC->>FC: FCDecryptWorker() immediately
        end
        
        FC->>FC: FCpEncDecrypt() - Decrypt with AES-CBC
        FC->>FC: Replace encrypted buffer with plaintext
        FC-->>FM: Decrypted data
    else
        FC->>FS: Forward read (no encryption)
        FS-->>FC: Plaintext data
        FC-->>FM: Plaintext data
    end
    FM-->>App: File data

    Note over App,FS: 💿 Volume Attachment
    FM->>FC: FCInstanceSetup(new_volume)
    FC->>FC: Check volume type (NTFS/FAT/etc.)
    FC->>FC: Check if removable media or desktop/mobile OS
    alt Volume qualifies for encryption
        FC->>FC: Create volume context
        FC->>FC: FCpEncVolumeStart() - Initialize AES provider
        FC->>FC: Set volume characteristics based on flags
        FC-->>FM: Attach successful
    else
        FC-->>FM: Do not attach
    end

    Note over FC: 🔐 Key Management
    FC->>StSec: StSecpGetChamberProfileKey(chamber_id)
    alt Key in cache
        StSec-->>FC: Cached key
    else
        StSec->>StSec: StSecpDeriveChamberProfileKey()
        StSec->>TPM: HMAC derive from master key
        TPM-->>StSec: Derived install & data keys
        StSec->>StSec: Cache keys
        StSec-->>FC: New key
    end`, []);

    // Render the diagram
    async function renderDiagram() {
        const element = document.getElementById('mermaid-diagram');
        element.innerHTML = '';
        const { svg } = await mermaid.render('sequence-diagram', diagramDefinition);
        element.innerHTML = svg;
    }

    // Show info panel
    function showInfo(type) {
        // Hide all panels
        document.querySelectorAll('.info-panel').forEach(panel => {
            panel.classList.remove('active');
        });

        // Show selected panel
        const panel = document.getElementById(`${type}-panel`);
        if (panel) {
            panel.classList.add('active');
            currentInfo = type;
        }
    }

    // Highlight specific flows
    function highlightFlow(flowType) {
        // Remove previous highlights
        clearHighlights();

        // Add active class to button
        document.querySelectorAll('.highlight-btn').forEach(btn => btn.classList.remove('active'));
        event.target.classList.add('active');

        // This is a simplified highlighting - in a real implementation,
        // you'd modify the SVG elements directly
        console.log(`Highlighting ${flowType} flow`);
    }

    function clearHighlights() {
        document.querySelectorAll('.highlight-btn').forEach(btn => btn.classList.remove('active'));
    }

    // Zoom controls
    function zoomIn() {
        currentZoom = Math.min(currentZoom + 0.2, 3);
        updateZoom();
    }

    function zoomOut() {
        currentZoom = Math.max(currentZoom - 0.2, 0.5);
        updateZoom();
    }

    function resetZoom() {
        currentZoom = 1;
        updateZoom();
    }

    function updateZoom() {
        const diagram = document.getElementById('mermaid-diagram');
        diagram.style.transform = `scale(${currentZoom})`;
    }

    // Add some interactivity to the diagram
    document.addEventListener('click', (e) => {
        if (e.target.closest('#mermaid-diagram')) {
            // Add click handlers for diagram elements
            console.log('Diagram element clicked:', e.target);
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        switch(e.key) {
            case '1':
                showInfo('overview');
                break;
            case '2':
                showInfo('components');
                break;
            case '3':
                showInfo('flows');
                break;
            case '4':
                showInfo('security');
                break;
            case '+':
            case '=':
                zoomIn();
                break;
            case '-':
                zoomOut();
                break;
            case '0':
                resetZoom();
                break;
        }
    });

    useEffect(() => {
        renderDiagram()
            .then(() => showInfo('overview'));
    }, []);

    return (
        <>
            <div className="container">
                <div className="diagram-container">
                    <div id="mermaid-diagram"></div>
                </div>

                <div className="flow-legend">
                    <h4>🎨 Flow Legend</h4>
                    <div className="legend-item">
                        <div className="legend-color" style={{background: '#667eea'}}></div>
                        <span>Synchronous Operations (Direct calls)</span>
                    </div>
                    <div className="legend-item">
                        <div className="legend-color" style={{background: '#f093fb'}}></div>
                        <span>Asynchronous Operations (Queued work)</span>
                    </div>
                    <div className="legend-item">
                        <div className="legend-color" style={{background: '#84fab0'}}></div>
                        <span>Security/Policy Operations</span>
                    </div>
                    <div className="legend-item">
                        <div className="legend-color" style={{background: '#ffecd2'}}></div>
                        <span>Cryptographic Operations</span>
                    </div>
                </div>
            </div>

            <div className="zoom-controls">
                <button className="zoom-btn" onClick={zoomIn}>+</button>
                <button className="zoom-btn" onClick={zoomOut}>−</button>
                <button className="zoom-btn" onClick={resetZoom}>⌂</button>
            </div>
        </>
    );
});

// Driver function data with call relationships
const FUNCTIONS_DATA = {
    // Main callbacks
    FCPreCreate: {
        name: 'FCPreCreate',
        category: 'fc',
        description: 'Pre-operation callback for file/directory creation. Determines encryption policy and performs security checks.',
        calls: ['FCpObtainSecurityInfoCallout', 'FCpAccessCheck', 'StSecGetSecurityDescriptor'],
        details: 'Main entry point for file creation operations. Constructs full file path, determines chamber assignment, and validates access permissions.',
        pos: {
            x: 50,
            y: 80
        }
    },
    FCPostCreate: {
        name: 'FCPostCreate',
        category: 'fc',
        description: 'Post-operation callback for file/directory creation. Sets up encryption infrastructure.',
        calls: ['FCpEncStreamStart'],
        details: 'Establishes stream context for encryption, initializes BCrypt key handles, and registers the stream with filter manager.',
        pos: {
            x: 50,
            y: 550
        }
    },
    FCPreRead: {
        name: 'FCPreRead',
        category: 'fc',
        description: 'Pre-operation callback for read operations. Prepares decryption context.',
        calls: [],
        details: 'Validates stream context exists, sets up completion context for post-operation decryption.',
        mobileOnly: true,
        pos: {
            x: 50,
            y: 40
        }
    },
    FCPostRead: {
        name: 'FCPostRead',
        category: 'fc',
        description: 'Post-operation callback for read operations. Performs decryption of data.',
        calls: ['FCDecryptWorker'],
        details: 'Manages decryption workflow, handles both synchronous and asynchronous decryption based on IRQL and data size.',
        mobileOnly: true,
        pos: {
            x: 50,
            y: 160
        }
    },
    FCPreWrite: {
        name: 'FCPreWrite',
        category: 'fc',
        description: 'Pre-operation callback for write operations. Encrypts data before writing to disk.',
        calls: ['FCpEncEncrypt'],
        details: 'Intercepts write operations, allocates shadow buffers, performs encryption, and redirects I/O to encrypted data.',
        mobileOnly: true
    },
    FCPostWrite: {
        name: 'FCPostWrite',
        category: 'fc',
        description: 'Post-operation callback for write operations. Cleanup encrypted buffers.',
        calls: ['FCFreeShadowBuffer'],
        details: 'Releases resources allocated during pre-write, frees encrypted buffers and completion contexts.',
        mobileOnly: true
    },

    // FC helper functions
    FCpObtainSecurityInfoCallout: {
        name: 'FCpObtainSecurityInfoCallout',
        category: 'fc',
        description: 'Determines encryption chamber and security descriptor for a file path.',
        calls: ['StSecGetSecurityDescriptor'],
        details: 'Core security policy resolution function. Maps file paths to encryption chambers and security descriptors.',
        pos: {
            x: 400,
            y: 40
        }
    },
    FCpAccessCheck: {
        name: 'FCpAccessCheck',
        category: 'fc',
        description: 'Performs access control checks using security descriptors.',
        calls: [],
        details: 'Validates user permissions against security descriptors, handles access modifications for encrypted files.',
        pos: {
            x: 400,
            y: 150
        }
    },
    FCpEncStreamStart: {
        name: 'FCpEncStreamStart',
        category: 'fc',
        description: 'Initializes encryption context for a file stream.',
        calls: ['StSecpGetChamberProfileKey', 'StSecpDeriveChamberProfileKey'],
        details: 'Sets up BCrypt key handles, retrieves or derives chamber-specific encryption keys.',
        pos: {
            x: 400,
            y: 550
        }
    },
    FCpEncEncrypt: {
        name: 'FCpEncEncrypt',
        category: 'fc',
        description: 'Encrypts data using AES-CBC before writing to disk.',
        calls: [],
        details: 'Performs sector-aligned AES-CBC encryption on write data, handles initialization vectors.'
    },
    FCpEncDecrypt: {
        name: 'FCpEncDecrypt',
        category: 'fc',
        description: 'Decrypts data read from disk using AES-CBC.',
        calls: [],
        details: 'Performs sector-aligned AES-CBC decryption on read data, handles zeroing offsets for security.',
        pos: {
            x: 550,
            y: 170
        }
    },
    FCDecryptWorker: {
        name: 'FCDecryptWorker',
        category: 'fc',
        description: 'Worker function for asynchronous decryption operations.',
        calls: ['FCpEncDecrypt'],
        details: 'Handles both immediate and queued decryption, manages MDL mapping and buffer access.',
        pos: {
            x: 300,
            y: 170
        }
    },
    FCFreeShadowBuffer: {
        name: 'FCFreeShadowBuffer',
        category: 'fc',
        description: 'Frees allocated shadow buffers used for encryption.',
        calls: [],
        details: 'Releases memory allocated for encrypted data buffers, handles both lookaside list and pool allocations.'
    },

    // StSec security functions
    StSecGetSecurityDescriptor: {
        name: 'StSecGetSecurityDescriptor',
        category: 'stsec',
        description: 'Main security policy lookup function. Returns security descriptor and chamber info.',
        calls: ['StSecpGetStorageFolderStringSecurityDescriptor', 'StSecpFindFolderPropertyPolicyElement'],
        details: 'Culmination of path-based security model. Resolves security descriptors and encryption chambers from policy cache.',
        pos: {
            x: 700,
            y: 100
        }
    },
    StSecpGetStorageFolderStringSecurityDescriptor: {
        name: 'StSecpGetStorageFolderStringSecurityDescriptor',
        category: 'stsec',
        description: 'Retrieves and processes security descriptor strings for folder paths.',
        calls: ['StSecpFindSecurityDescriptorPolicyElement', 'StSecpGetParameterValue', 'StSecpCheckConditionalPolicy'],
        details: 'Finds matching security policies, processes parameters in templates, constructs final security descriptor strings.',
        pos: {
            x: 980,
            y: 40
        }
    },
    StSecpFindSecurityDescriptorPolicyElement: {
        name: 'StSecpFindSecurityDescriptorPolicyElement',
        category: 'stsec',
        description: 'Searches security descriptor cache for matching path patterns.',
        calls: [],
        details: 'Performs path pattern matching including parameterized segments like <PackageFamilyName>.',
        pos: {
            x: 1400,
            y: 40
        }
    },
    StSecpFindFolderPropertyPolicyElement: {
        name: 'StSecpFindFolderPropertyPolicyElement',
        category: 'stsec',
        description: 'Searches folder property cache for encryption chamber assignments.',
        calls: [],
        details: 'Simple path matching to determine chamber assignments for specific folders.',
        pos: {
            x: 980,
            y: 150
        }
    },
    StSecpGetChamberProfileKey: {
        name: 'StSecpGetChamberProfileKey',
        category: 'stsec',
        description: 'Retrieves cached encryption keys for a chamber.',
        calls: [],
        details: 'Looks up chamber-specific encryption keys from memory cache, updates access timestamps.',
        pos: {
            x: 700,
            y: 500
        }
    },
    StSecpDeriveChamberProfileKey: {
        name: 'StSecpDeriveChamberProfileKey',
        category: 'stsec',
        description: 'Derives new encryption keys for chambers using HMAC-based key derivation.',
        calls: ['StSecpGetMasterKey', 'StSecpAddChamberProfileKey'],
        details: 'Creates Install and Data keys from master key using HMAC-SHA256, adds to cache.',
        pos: {
            x: 700,
            y: 600
        }
    },
    StSecpGetMasterKey: {
        name: 'StSecpGetMasterKey',
        category: 'stsec',
        description: 'Retrieves or generates the master encryption key.',
        calls: ['StSecpReadSealedKeyBlob', 'StSecpUnsealKey', 'StSecpSealKey', 'StSecpWriteSealedKeyBlob'],
        details: 'Manages TPM-sealed master key lifecycle: generation, sealing, unsealing, and persistence.',
        pos: {
            x: 1100,
            y: 530
        }
    },
    StSecpAddChamberProfileKey: {
        name: 'StSecpAddChamberProfileKey',
        category: 'stsec',
        description: 'Adds derived encryption keys to the memory cache.',
        calls: [],
        details: 'Stores chamber keys in generic table cache, manages cache size and cleanup triggers.',
        pos: {
            x: 1100,
            y: 630
        }
    },
    StSecpGetParameterValue: {
        name: 'StSecpGetParameterValue',
        category: 'stsec',
        description: 'Converts parameter types to Security Identifiers (SIDs).',
        calls: ['StSecpGetSidFromUserName', 'StSecpGetSidFromPackageFamilyName', 'KappxGetSecurityDescriptorStringForPackageFullName', 'StSecpGetSidFromPackageFullName', 'StSecpGetSidFromProductId'],
        details: 'Handles different identifier types: usernames, package names, product IDs, converting them to SIDs.',
        pos: {
            x: 1400,
            y: 120
        }
    },
    StSecpGetSidFromPackageFamilyName: {
        name: 'StSecpGetSidFromPackageFamilyName',
        category: 'stsec',
        description: 'Generates SID from Windows Store app package family name.',
        calls: ['KappxGetPackageSidFromPackageFamilyNameInRegistry', 'StSecpGetAppSid'],
        details: 'Tries registry lookup first, falls back to algorithmic SID generation using cryptographic hashing.',
        pos: {
            x: 1900,
            y: 140
        }
    },
    StSecpGetSidFromPackageFullName: {
        name: 'StSecpGetSidFromPackageFullName',
        category: 'stsec',
        description: 'Extracts family name from full package name and generates SID.',
        calls: ['StSecpPackageFamilyNameFromFullName', 'StSecpGetSidFromPackageFamilyName'],
        details: 'Parses full package name format to extract family name component.',
        pos: {
            x: 1850,
            y: 290
        }
    },
    StSecpGetSidFromProductId: {
        name: 'StSecpGetSidFromProductId',
        category: 'stsec',
        description: 'Generates SID from product ID.',
        calls: ['StSecpGetAppSid'],
        details: 'Converts product IDs to uppercase and generates deterministic SIDs.',
        pos: {
            x: 1850,
            y: 360
        }
    },
    StSecpGetSidFromUserName: {
        name: 'StSecpGetSidFromUserName',
        category: 'stsec',
        description: 'Copies username as SID (simplified implementation).',
        calls: [],
        details: 'Simple username copying rather than true SID conversion.',
        pos: {
            x: 1850,
            y: 80
        }
    },
    StSecpGetAppSid: {
        name: 'StSecpGetAppSid',
        category: 'stsec',
        description: 'Generates deterministic SID using cryptographic hashing.',
        calls: [],
        details: 'Uses SHA-256 hash to create consistent SIDs with custom authority (S-1-15-2-...).',
        pos: {
            x: 2350,
            y: 120
        }
    },
    StSecpPackageFamilyNameFromFullName: {
        name: 'StSecpPackageFamilyNameFromFullName',
        category: 'stsec',
        description: 'Extracts package family name from full package name.',
        calls: [],
        details: 'Parses Windows Store package naming format, extracts PublisherName.AppName_PublisherID.',
        pos: {
            x: 2350,
            y: 290
        }
    },
    StSecpCheckConditionalPolicy: {
        name: 'StSecpCheckConditionalPolicy',
        category: 'stsec',
        description: 'Checks if package is in debug profile registry.',
        calls: [],
        details: 'Determines debug mode status by checking registry key existence.',
        pos: {
            x: 1400,
            y: 200
        }
    },
    StSecpSealKey: {
        name: 'StSecpSealKey',
        category: 'stsec',
        description: 'Seals encryption key using TPM for secure storage.',
        calls: [],
        details: 'Uses TPM to create sealed key blob that can only be unsealed by the same TPM.',
        pos: {
            x: 1500,
            y: 590
        }
    },
    StSecpUnsealKey: {
        name: 'StSecpUnsealKey',
        category: 'stsec',
        description: 'Unseals TPM-protected encryption key.',
        calls: [],
        details: 'Decrypts sealed key blob using TPM, restoring original master key.',
        pos: {
            x: 1500,
            y: 520
        }
    },
    StSecpReadSealedKeyBlob: {
        name: 'StSecpReadSealedKeyBlob',
        category: 'stsec',
        description: 'Reads sealed key blob from registry storage.',
        calls: [],
        details: 'Retrieves encrypted master key from registry at fixed storage location.',
        pos: {
            x: 1500,
            y: 450
        }
    },
    StSecpWriteSealedKeyBlob: {
        name: 'StSecpWriteSealedKeyBlob',
        category: 'stsec',
        description: 'Writes sealed key blob to registry storage.',
        calls: [],
        details: 'Persists encrypted master key to registry for future use.',
        pos: {
            x: 1500,
            y: 660
        }
    },

    // Kappx Windows App Package functions
    KappxGetSecurityDescriptorStringForPackageFullName: {
        name: 'KappxGetSecurityDescriptorStringForPackageFullName',
        category: 'kappx',
        description: 'Obtains security descriptor for Windows Store app package.',
        calls: ['KappxGetPackageRootPathForPackageFullName'],
        details: 'Retrieves security descriptor from package directory or provides default SDDL string.',
        pos: {
            x: 1850,
            y: 210
        }
    },
    KappxGetPackageRootPathForPackageFullName: {
        name: 'KappxGetPackageRootPathForPackageFullName',
        category: 'kappx',
        description: 'Locates filesystem path where Windows Store app is installed.',
        calls: [],
        details: 'Constructs full path to package installation directory using registry PackageRoot value.',
        pos: {
            x: 2350,
            y: 210
        }
    },
    KappxGetPackageSidFromPackageFamilyNameInRegistry: {
        name: 'KappxGetPackageSidFromPackageFamilyNameInRegistry',
        category: 'kappx',
        description: 'Extracts app SID from registry using package family name.',
        calls: [],
        details: 'Queries PackageSidRef registry key to retrieve stored SID for Windows Store app.',
        pos: {
            x: 2350,
            y: 50
        }
    }
};

// Define the callback flows
const CALLBACK_FLOWS = {
    desktop: {
        'File Create/Open': ['FCPreCreate', 'FCPostCreate']
    },
    mobile: {
        'File Create/Open': ['FCPreCreate', 'FCPostCreate'],
        'File Read': ['FCPreRead', 'FCPostRead'],
        'File Write': ['FCPreWrite', 'FCPostWrite']
    }
};

// Component for rendering function nodes
const FunctionNode = ({func, isSelected, onClick, position, isDimmed}) => {
    const getCategoryColor = (category) => {
        switch (category) {
            case 'fc':
                return 'bg-blue-100 border-blue-300 text-blue-800';
            case 'stsec':
                return 'bg-green-100 border-green-300 text-green-800';
            case 'kappx':
                return 'bg-purple-100 border-purple-300 text-purple-800';
            default:
                return 'bg-gray-100 border-gray-300 text-gray-800';
        }
    };

    return (
        <div
            className={`
        absolute cursor-pointer transition-all duration-200 transform hover:scale-105
        ${getCategoryColor(func.category)}
        ${isSelected ? 'ring-2 ring-offset-2 ring-blue-500 shadow-lg' : 'shadow-md'}
        ${isDimmed ? 'opacity-40' : 'opacity-100'}
        border-2 rounded-lg px-3 py-2 min-w-[140px] text-center font-medium text-sm 
      `}
            style={{left: position.x, top: position.y}}
            onClick={() => onClick(func)}
        >
            {func.name}
            {func.mobileOnly && (
                <div className="text-xs mt-1 opacity-70">📱 Mobile Only</div>
            )}
        </div>
    );
};

// Component for rendering connection lines
const ConnectionLine = ({textLength, from, to}) => {
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    const midX = from.x + dx / 2;
    const midY = from.y + dy / 2;

    const mulLength = textLength * 8;
    const addedX = mulLength < 140 ? 140 : mulLength;

    return (
        <svg
            className="absolute top-0 left-0 pointer-events-none"
            style={{width: '100%', height: '100%'}}
        >
            <defs>
                <marker
                    id="arrowhead"
                    markerWidth="10"
                    markerHeight="7"
                    refX="9"
                    refY="3.5"
                    orient="auto"
                >
                    <polygon points="0 0, 10 3.5, 0 7" fill="#6b7280"/>
                </marker>
            </defs>
            <path
                d={`M ${from.x + addedX} ${from.y + 20} Q ${midX} ${midY} ${to.x} ${to.y + 20}`}
                stroke="#6b7280"
                strokeWidth="2"
                fill="none"
                markerEnd="url(#arrowhead)"
            />
        </svg>
    );
};

// Main component
const FileCryptDriverExplorer = () => {
    const [currentTab, setCurrentTab] = useState(1);
    const [platform, setPlatform] = useState('desktop');
    const [selectedCallback, setSelectedCallback] = useState('File Create/Open');
    const [selectedFunction, setSelectedFunction] = useState(null);
    const [isPlaying, setIsPlaying] = useState(false);
    const [currentStep, setCurrentStep] = useState(0);

    // Get available callbacks for current platform
    const availableCallbacks = CALLBACK_FLOWS[platform];

    // Reset selection when platform changes
    React.useEffect(() => {
        const callbacks = Object.keys(CALLBACK_FLOWS[platform]);
        setSelectedCallback(callbacks[0]);
        setSelectedFunction(null);
        setCurrentStep(0);
        setIsPlaying(false);
    }, [platform]);

    // Get the flow for the selected callback
    const getCurrentFlow = useCallback(() => {
        const rootFunctions = availableCallbacks[selectedCallback] || [];
        const visited = new Set();
        const flow = [];

        const traverse = (funcNames, depth = 0) => {
            funcNames.forEach(funcName => {
                if (!visited.has(funcName) && FUNCTIONS_DATA[funcName]) {
                    visited.add(funcName);
                    flow.push({func: FUNCTIONS_DATA[funcName], depth});

                    // Add called functions
                    const calledFunctions = FUNCTIONS_DATA[funcName].calls || [];
                    if (calledFunctions.length > 0) {
                        traverse(calledFunctions, depth + 1);
                    }
                }
            });
        };

        traverse(rootFunctions);
        return flow;
    }, [availableCallbacks, selectedCallback]);

    const currentFlow = getCurrentFlow();

    // Calculate positions for flow diagram - vertically
    const calculatePositions = useMemo(() => {
        const positions = {};
        let currentY = 50;
        const depthX = {};

        currentFlow.forEach(({func, depth}) => {
            if (!depthX[depth]) {
                depthX[depth] = 0;
            }

            positions[func.name] = func.pos ?? {
                x: (depth * 380) + 50,
                y: currentY + depthX[depth] * 100
            };

            depthX[depth]++;
        });

        return positions;
    }, [currentFlow]);

    // Animation logic
    const handlePlay = () => {
        if (isPlaying) {
            setIsPlaying(false);
            return;
        }

        setIsPlaying(true);
        setCurrentStep(0);

        const interval = setInterval(() => {
            setCurrentStep(prev => {
                if (prev >= currentFlow.length - 1) {
                    setIsPlaying(false);
                    clearInterval(interval);
                    return prev;
                }
                return prev + 1;
            });
        }, 1000);
    };

    const handleReset = () => {
        setIsPlaying(false);
        setCurrentStep(0);
        setSelectedFunction(null);
    };

    // Filter functions based on mobile compatibility
    const visibleFunctions = currentFlow.filter(({func}) => {
        if (platform === 'desktop' && func.mobileOnly) {
            return false;
        }
        return true;
    });

    return (
        <div className="min-h-screen bg-gray-50 h-full flex flex-col">
            {/* Header */}
            <div className="bg-white shadow-sm border-b">
                <div className="max-w-7xl mx-auto px-6 py-8">
                    <h1 className="text-4xl font-bold text-gray-900 mb-4">FileCrypt Driver Explorer</h1>
                    <p className="text-lg text-gray-600 mb-2">
                        Interactive Research Showcase • Windows Kernel File System Filter Driver
                    </p>
                    <div className="flex items-center space-x-4 text-sm text-gray-500">
                        <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded">Desktop OS Mode: Registers only Create callbacks (FCPreCreate, FCPostCreate) - Read/Write operations are not intercepted</span>
                    </div>
                </div>
            </div>

            <div className="flex items-center justify-center bg-gray-100 rounded-lg p-2 space-x-4">
                <button
                    onClick={() => setCurrentTab(1)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                        currentTab === 1
                            ? 'bg-white text-blue-600 shadow-sm'
                            : 'text-gray-600 hover:text-gray-800'
                    }`}
                >
                    <Workflow size={24}/>
                    <span className="text-xl">Flow Chart</span>
                </button>
                <button
                    onClick={() => setCurrentTab(2)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                        currentTab === 2
                            ? 'bg-white text-blue-600 shadow-sm'
                            : 'text-gray-600 hover:text-gray-800'
                    }`}
                >
                    <ChartNetwork size={24}/>
                    <span className="text-xl">Sequence Diagram</span>
                </button>
            </div>

            {/* Controls */}

            {
                currentTab === 1 && (
                    <div className="px-6 py-6 flex flex-col flex-1">
                        <div className="bg-white rounded-lg shadow-sm border p-6 mb-6">
                            <h2 className="text-xl font-semibold mb-4">Chart Controls</h2>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                                {/* Platform Toggle */}
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">Platform</label>
                                    <div className="flex bg-gray-100 rounded-lg p-1">
                                        <button
                                            onClick={() => setPlatform('desktop')}
                                            className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                                                platform === 'desktop'
                                                    ? 'bg-white text-blue-600 shadow-sm'
                                                    : 'text-gray-600 hover:text-gray-800'
                                            }`}
                                        >
                                            <Monitor size={16}/>
                                            <span>Desktop OS</span>
                                        </button>
                                        <button
                                            onClick={() => setPlatform('mobile')}
                                            className={`flex items-center space-x-2 px-4 py-2 rounded-md transition-colors ${
                                                platform === 'mobile'
                                                    ? 'bg-white text-blue-600 shadow-sm'
                                                    : 'text-gray-600 hover:text-gray-800'
                                            }`}
                                        >
                                            <Smartphone size={16}/>
                                            <span>Mobile OS</span>
                                        </button>
                                    </div>
                                </div>

                                {/* Operation Selector */}
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">Operation</label>
                                    <select
                                        value={selectedCallback}
                                        onChange={(e) => {
                                            setSelectedCallback(e.target.value);
                                            setSelectedFunction(null);
                                            setCurrentStep(0);
                                            setIsPlaying(false);
                                        }}
                                        className="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    >
                                        {Object.keys(availableCallbacks).map(callback => (
                                            <option key={callback} value={callback}>{callback}</option>
                                        ))}
                                    </select>
                                </div>

                                {/* Animation Controls */}
                                <div>
                                    <label className="block text-sm font-medium text-gray-700 mb-2">Animation</label>
                                    <div className="flex space-x-2">
                                        <button
                                            onClick={handlePlay}
                                            className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
                                        >
                                            {isPlaying ? <Square size={16}/> : <Play size={16}/>}
                                            <span>{isPlaying ? 'Stop' : 'Start'}</span>
                                        </button>
                                        <button
                                            onClick={handleReset}
                                            className="flex items-center space-x-2 px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
                                        >
                                            <RotateCcw size={16}/>
                                            <span>Reset</span>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
                            {/* Flow Diagram */}
                            <div className="lg:col-span-2 flex flex-col">
                                <div className="bg-white rounded-lg shadow-sm border flex-1 flex flex-col">
                                    <div className="border-b p-4">
                                        <h3 className="text-lg font-semibold">Driver Function Flow Chart</h3>
                                        <p className="text-sm text-gray-600 mt-1">
                                            {selectedCallback} - {visibleFunctions.length} functions
                                        </p>
                                    </div>

                                    <div className="relative h-96 overflow-auto p-4 flex-1">
                                        {visibleFunctions.map(({func}, index) => {
                                            const position = calculatePositions[func.name];
                                            if (!position) return null;

                                            const isDimmed = isPlaying && index > currentStep;

                                            return (
                                                <FunctionNode
                                                    key={func.name}
                                                    func={func}
                                                    isSelected={selectedFunction?.name === func.name}
                                                    onClick={setSelectedFunction}
                                                    position={position}
                                                    isDimmed={isDimmed}
                                                />
                                            );
                                        })}

                                        {/* Draw connection lines */}
                                        {visibleFunctions.map(({func}) => {
                                            const fromPos = calculatePositions[func.name];
                                            if (!fromPos) return null;

                                            return func.calls?.map(calledFuncName => {
                                                const toPos = calculatePositions[calledFuncName];
                                                if (!toPos || (platform === 'desktop' && FUNCTIONS_DATA[calledFuncName]?.mobileOnly)) return null;

                                                return (
                                                    <ConnectionLine
                                                        key={`${func.name}-${calledFuncName}`}
                                                        textLength={func.name.length}
                                                        from={fromPos}
                                                        to={toPos}
                                                    />
                                                );
                                            });
                                        })}
                                    </div>
                                </div>
                            </div>

                            {/* Function Details */}
                            <div>
                                <div className="bg-white rounded-lg shadow-sm border">
                                    <div className="border-b p-4">
                                        <h3 className="text-lg font-semibold">Function Details</h3>
                                    </div>

                                    <div className="p-4">
                                        {selectedFunction ? (
                                            <div className="space-y-4">
                                                <div>
                                                    <h4 className="font-semibold text-lg text-blue-600">{selectedFunction.name}</h4>
                                                    <span
                                                        className={`inline-block px-2 py-1 rounded text-xs font-medium mt-1 ${
                                                            selectedFunction.category === 'fc' ? 'bg-blue-100 text-blue-800' :
                                                                selectedFunction.category === 'stsec' ? 'bg-green-100 text-green-800' :
                                                                    'bg-purple-100 text-purple-800'
                                                        }`}
                                                    >
                                                {selectedFunction.category.toUpperCase()}
                                            </span>
                                                    {selectedFunction.mobileOnly && (
                                                        <span
                                                            className="inline-block ml-2 px-2 py-1 bg-orange-100 text-orange-800 rounded text-xs font-medium">
                                                    📱 Mobile Only
                                                </span>
                                                    )}
                                                </div>

                                                <div>
                                                    <h5 className="font-medium text-gray-900 mb-2">Description</h5>
                                                    <p className="text-gray-700 text-sm">{selectedFunction.description}</p>
                                                </div>

                                                <div>
                                                    <h5 className="font-medium text-gray-900 mb-2">Implementation
                                                        Details</h5>
                                                    <p className="text-gray-600 text-sm">{selectedFunction.details}</p>
                                                </div>

                                                {selectedFunction.calls && selectedFunction.calls.length > 0 && (
                                                    <div>
                                                        <h5 className="font-medium text-gray-900 mb-2">Calls
                                                            ({selectedFunction.calls.length})</h5>
                                                        <ul className="text-sm space-y-1">
                                                            {selectedFunction.calls.map(calledFunc => (
                                                                <li key={calledFunc}
                                                                    className="text-blue-600 hover:text-blue-800 cursor-pointer"
                                                                    onClick={() => setSelectedFunction(FUNCTIONS_DATA[calledFunc])}>
                                                                    → {calledFunc}
                                                                </li>
                                                            ))}
                                                        </ul>
                                                    </div>
                                                )}
                                            </div>
                                        ) : (
                                            <div className="text-center text-gray-500 py-8">
                                                <p>Click on a function in the diagram to view details</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )
            }
            {
                currentTab === 2 && (
                    <SequenceDiagram/>
                )
            }
        </div>
    );
};

ReactDOM.createRoot(document.getElementById('root')).render(
    <FileCryptDriverExplorer/>
);