import React, {useState, useEffect} from 'react';
import ReactDOM from 'react-dom/client'
import {ChevronRight, FileText, Shield, Key, Cpu, Smartphone, Monitor, Play, Pause, RotateCcw} from 'lucide-react';


const components = {
    // Entry Point
    driver_entry: {
        title: "DriverEntry",
        description: "Main entry point",
        file: "fc.c",
        functions: ["DriverEntry"],
        details: "Driver initialization and setup."
    },
    fsrtl_is_mobile: {
        title: "FsRtlIsMobileOS",
        description: "Platform detection",
        file: "ntoskrnl.exe",
        functions: ["FsRtlIsMobileOS"],
        details: "Determines if running on Mobile OS - critical for callback registration decision."
    },
    fc_read_params: {
        title: "FCReadDriverParameters",
        description: "Registry configuration",
        file: "fc.c",
        functions: ["FCReadDriverParameters"],
        details: "Reads driver configuration flags from registry."
    },
    stsec_init: {
        title: "StSecInitialize",
        description: "Security subsystem init",
        file: "stsec.c",
        functions: ["StSecInitialize"],
        details: "Initializes security module, TPM providers, and policy cache."
    },

    // Create Flow
    fc_pre_create: {
        title: "FCPreCreate",
        description: "Create operation intercept",
        file: "fc.c",
        functions: ["FCPreCreate"],
        details: "Intercepts file creation/opening operations."
    },
    fc_obtain_security: {
        title: "FCpObtainSecurityInfoCallout",
        description: "Security context resolution",
        file: "fc.c",
        functions: ["FCpObtainSecurityInfoCallout"],
        details: "Determines security descriptor and chamber assignment."
    },
    stsec_get_descriptor: {
        title: "StSecGetSecurityDescriptor",
        description: "Security policy lookup",
        file: "stsec.c",
        functions: ["StSecGetSecurityDescriptor"],
        details: "Retrieves security descriptor and chamber ID for file path."
    },
    stsec_find_policy: {
        title: "StSecpFindSecurityDescriptorPolicyElement",
        description: "Policy element matching",
        file: "stsec.c",
        functions: ["StSecpFindSecurityDescriptorPolicyElement"],
        details: "Finds matching security policy using path pattern matching."
    },
    stsec_find_folder: {
        title: "StSecpFindFolderPropertyPolicyElement",
        description: "Folder property lookup",
        file: "stsec.c",
        functions: ["StSecpFindFolderPropertyPolicyElement"],
        details: "Finds folder-specific encryption properties."
    },
    kappx_get_sid: {
        title: "KappxGetPackageSidFromPackageFamilyNameInRegistry",
        description: "UWP app SID resolution",
        file: "kappx.c",
        functions: ["KappxGetPackageSidFromPackageFamilyNameInRegistry"],
        details: "Gets Security Identifier for Windows Store apps."
    },
    fc_access_check: {
        title: "FCpAccessCheck",
        description: "Access validation",
        file: "fc.c",
        functions: ["FCpAccessCheck"],
        details: "Validates access permissions using security descriptors."
    },
    fc_post_create: {
        title: "FCPostCreate",
        description: "Create completion",
        file: "fc.c",
        functions: ["FCPostCreate"],
        details: "Sets up encryption context for the opened file."
    },
    fc_enc_stream_start: {
        title: "FCpEncStreamStart",
        description: "Stream encryption setup",
        file: "fc.c",
        functions: ["FCpEncStreamStart"],
        details: "Initializes encryption keys for the file stream."
    },
    stsec_get_chamber_key: {
        title: "StSecpGetChamberProfileKey",
        description: "Chamber key retrieval",
        file: "stsec.c",
        functions: ["StSecpGetChamberProfileKey"],
        details: "Gets cached chamber key or derives new one."
    },
    stsec_derive_key: {
        title: "StSecpDeriveChamberProfileKey",
        description: "Key derivation",
        file: "stsec.c",
        functions: ["StSecpDeriveChamberProfileKey"],
        details: "Derives chamber-specific keys from master key using HMAC."
    },
    stsec_get_master: {
        title: "StSecpGetMasterKey",
        description: "Master key access",
        file: "stsec.c",
        functions: ["StSecpGetMasterKey"],
        details: "Retrieves or generates TPM-sealed master key."
    },

    // Read Flow (Mobile Only)
    fc_pre_read: {
        title: "FCPreRead",
        description: "Read operation setup",
        file: "fc.c",
        functions: ["FCPreRead"],
        details: "Prepares for file read operation and decryption."
    },
    fc_post_read: {
        title: "FCPostRead",
        description: "Read completion",
        file: "fc.c",
        functions: ["FCPostRead"],
        details: "Handles read completion and decryption."
    },
    fc_decrypt_worker: {
        title: "FCDecryptWorker",
        description: "Decryption worker",
        file: "fc.c",
        functions: ["FCDecryptWorker"],
        details: "Worker function that performs actual decryption."
    },
    fc_enc_decrypt: {
        title: "FCpEncDecrypt",
        description: "AES decryption",
        file: "fc.c",
        functions: ["FCpEncDecrypt"],
        details: "Performs AES-CBC decryption of file data."
    },

    // Write Flow (Mobile Only)
    fc_pre_write: {
        title: "FCPreWrite",
        description: "Write operation intercept",
        file: "fc.c",
        functions: ["FCPreWrite"],
        details: "Intercepts write operations and encrypts data."
    },
    fc_enc_encrypt: {
        title: "FCpEncEncrypt",
        description: "AES encryption",
        file: "fc.c",
        functions: ["FCpEncEncrypt"],
        details: "Performs AES-CBC encryption of file data."
    },
    fc_post_write: {
        title: "FCPostWrite",
        description: "Write completion",
        file: "fc.c",
        functions: ["FCPostWrite"],
        details: "Cleanup after write operation completion."
    },

    // TPM Operations
    stsec_seal_key: {
        title: "StSecpSealKey",
        description: "TPM key sealing",
        file: "stsec.c",
        functions: ["StSecpSealKey"],
        details: "Seals master key using TPM hardware."
    },
    stsec_unseal_key: {
        title: "StSecpUnsealKey",
        description: "TPM key unsealing",
        file: "stsec.c",
        functions: ["StSecpUnsealKey"],
        details: "Unseals master key from TPM hardware."
    }
};

const operationFlows = {
    create: [
        {component: 'driver_entry', step: 'Driver initialization'},
        {component: 'fsrtl_is_mobile', step: 'Check if Mobile OS'},
        {component: 'fc_read_params', step: 'Read registry configuration'},
        {component: 'stsec_init', step: 'Initialize security subsystem'},
        {component: 'fc_pre_create', step: 'Intercept file create/open'},
        {component: 'fc_obtain_security', step: 'Resolve security context'},
        {component: 'stsec_get_descriptor', step: 'Get security descriptor'},
        {component: 'stsec_find_policy', step: 'Find matching policy'},
        {component: 'stsec_find_folder', step: 'Check folder properties'},
        {component: 'kappx_get_sid', step: 'Resolve UWP app SID (if applicable)'},
        {component: 'fc_access_check', step: 'Validate access permissions'},
        {component: 'fc_post_create', step: 'Complete create operation'},
        {component: 'fc_enc_stream_start', step: 'Setup stream encryption'},
        {component: 'stsec_get_chamber_key', step: 'Get chamber key from cache'},
        {component: 'stsec_derive_key', step: 'Derive key if not cached'},
        {component: 'stsec_get_master', step: 'Access TPM master key'}
    ],
    read: [
        {component: 'fc_pre_read', step: 'Setup read operation'},
        {component: 'stsec_get_chamber_key', step: 'Get decryption key'},
        {component: 'fc_post_read', step: 'Handle read completion'},
        {component: 'fc_decrypt_worker', step: 'Queue decryption work'},
        {component: 'fc_enc_decrypt', step: 'Perform AES-CBC decryption'}
    ],
    write: [
        {component: 'fc_pre_write', step: 'Intercept write operation'},
        {component: 'stsec_get_chamber_key', step: 'Get encryption key'},
        {component: 'fc_enc_encrypt', step: 'Perform AES-CBC encryption'},
        {component: 'fc_post_write', step: 'Cleanup after write'}
    ]
};

const getComponentPosition = (componentId) => {
    const positions = {
        // Entry/Init Row (Top)
        driver_entry: {x: 15, y: 8},
        fsrtl_is_mobile: {x: 35, y: 8},
        fc_read_params: {x: 55, y: 8},
        stsec_init: {x: 75, y: 8},

        // Create Flow - Security Resolution
        fc_pre_create: {x: 10, y: 20},
        fc_obtain_security: {x: 25, y: 20},
        stsec_get_descriptor: {x: 40, y: 20},
        stsec_find_policy: {x: 55, y: 20},
        stsec_find_folder: {x: 70, y: 20},
        kappx_get_sid: {x: 85, y: 20},

        // Create Flow - Access & Completion
        fc_access_check: {x: 20, y: 32},
        fc_post_create: {x: 40, y: 32},
        fc_enc_stream_start: {x: 60, y: 32},

        // Key Management
        stsec_get_chamber_key: {x: 15, y: 44},
        stsec_derive_key: {x: 35, y: 44},
        stsec_get_master: {x: 55, y: 44},

        // Read Flow (Mobile Only)
        fc_pre_read: {x: 10, y: 56},
        fc_post_read: {x: 30, y: 56},
        fc_decrypt_worker: {x: 50, y: 56},
        fc_enc_decrypt: {x: 70, y: 56},

        // Write Flow (Mobile Only)
        fc_pre_write: {x: 10, y: 68},
        fc_enc_encrypt: {x: 35, y: 68},
        fc_post_write: {x: 60, y: 68},

        // TPM Operations (Bottom)
        stsec_seal_key: {x: 25, y: 80},
        stsec_unseal_key: {x: 55, y: 80}
    };
    return positions[componentId] || {x: 50, y: 50};
};

const ComponentNode = ({id, component, isActive, isSelected, onClick, isMobile, activeOperation, animationStep}) => {
    const position = getComponentPosition(id);

    // Determine if component is available based on platform
    const isReadWriteComponent = ['pre_read', 'post_read', 'pre_write', 'post_write'].includes(id);
    const isAvailable = isMobile || !isReadWriteComponent;

    return (
        <div
            className={`absolute transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all duration-300 ${
                isActive ? 'scale-110 z-20' : 'z-10'
            } ${!isAvailable ? 'opacity-40' : ''}`}
            style={{left: `${position.x}%`, top: `${position.y}%`}}
            onClick={() => onClick(id)}
        >
            <div className={`
          px-4 py-3 rounded-lg border-2 transition-all duration-300 shadow-lg min-w-[120px] text-center
          ${!isAvailable ? 'border-gray-200 bg-gray-100' : ''}
          ${isActive ? 'border-blue-500 bg-blue-100 scale-110' : ''}
          ${isSelected ? 'border-purple-500 bg-purple-50' : isAvailable ? 'border-gray-300 bg-white hover:border-gray-400 hover:bg-gray-50' : ''}
        `}>
                <div className={`text-sm font-semibold ${isAvailable ? 'text-gray-800' : 'text-gray-400'}`}>
                    {component.title}
                </div>
                <div className={`text-xs mt-1 ${isAvailable ? 'text-gray-600' : 'text-gray-400'}`}>
                    {component.file}
                </div>
                {!isAvailable && (
                    <div className="text-xs text-red-500 mt-1 font-medium">Mobile Only</div>
                )}
            </div>
            {isActive && (
                <div
                    className="absolute top-full left-1/2 transform -translate-x-1/2 mt-2 bg-blue-600 text-white px-3 py-1 rounded text-xs whitespace-nowrap">
                    {operationFlows[activeOperation][animationStep]?.step}
                </div>
            )}
        </div>
    );
};

const FileCryptExplorer = () => {
    const [selectedComponent, setSelectedComponent] = useState(null);
    const [activeOperation, setActiveOperation] = useState('create');
    const [isMobile, setIsMobile] = useState(false);
    const [animationStep, setAnimationStep] = useState(0);
    const [isAnimating, setIsAnimating] = useState(false);

    useEffect(() => {
        let interval;
        if (isAnimating) {
            interval = setInterval(() => {
                setAnimationStep(prev => {
                    const maxSteps = operationFlows[activeOperation].length;
                    return prev >= maxSteps - 1 ? 0 : prev + 1;
                });
            }, 2000);
        }
        return () => clearInterval(interval);
    }, [isAnimating, activeOperation]);

    // Reset to 'create' operation when switching to Desktop OS if Read/Write is selected
    useEffect(() => {
        if (!isMobile && (activeOperation === 'read' || activeOperation === 'write')) {
            setActiveOperation('create');
            setIsAnimating(false);
            setAnimationStep(0);
        }
    }, [isMobile, activeOperation]);

    const startAnimation = () => {
        // Don't start animation for read/write operations on desktop
        if (!isMobile && (activeOperation === 'read' || activeOperation === 'write')) {
            return;
        }
        setIsAnimating(true);
        setAnimationStep(0);
    };

    const stopAnimation = () => {
        setIsAnimating(false);
    };

    const resetAnimation = () => {
        setIsAnimating(false);
        setAnimationStep(0);
    };

    const isComponentActive = (componentId) => {
        if (!isAnimating) {
            return false;
        }

        const currentFlow = operationFlows[activeOperation];
        return currentFlow[animationStep]?.component === componentId;
    };

    const onComponentClick = (componentId) => {
        setSelectedComponent(selectedComponent === componentId ? null : componentId);
    };

    return (
        <div className="p-6 bg-gradient-to-br from-blue-50 to-purple-50 min-h-screen">
            <div className="text-center mb-8">
                <h1 className="text-4xl font-bold text-gray-800 mb-2">FileCrypt Driver Explorer</h1>
                <p className="text-lg text-gray-600">Interactive Research Showcase - Windows Kernel File System Filter
                    Driver</p>
            </div>

            {/* Controls */}
            <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
                <div className="flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                            <label className="text-sm font-medium">Platform:</label>
                            <button
                                onClick={() => setIsMobile(!isMobile)}
                                className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-colors ${
                                    isMobile ? 'bg-blue-100 text-blue-700' : 'bg-gray-100 text-gray-700'
                                }`}
                            >
                                {isMobile ? <Smartphone size={16}/> : <Monitor size={16}/>}
                                {isMobile ? 'Mobile OS' : 'Desktop OS'}
                            </button>
                        </div>

                        <div className="flex items-center gap-2">
                            <label className="text-sm font-medium">Operation:</label>
                            <select
                                value={activeOperation}
                                onChange={(e) => setActiveOperation(e.target.value)}
                                className="px-3 py-2 border rounded-lg bg-white"
                            >
                                <option value="create">File Create/Open</option>
                                {isMobile && <option value="read">File Read</option>}
                                {isMobile && <option value="write">File Write</option>}
                            </select>
                        </div>
                    </div>

                    <div className="flex items-center gap-2">
                        <button
                            onClick={startAnimation}
                            disabled={isAnimating || (!isMobile && (activeOperation === 'read' || activeOperation === 'write'))}
                            className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
                        >
                            <Play size={16}/>
                            Start
                        </button>
                        <button
                            onClick={stopAnimation}
                            disabled={!isAnimating}
                            className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50"
                        >
                            <Pause size={16}/>
                            Stop
                        </button>
                        <button
                            onClick={resetAnimation}
                            className="flex items-center gap-2 px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
                        >
                            <RotateCcw size={16}/>
                            Reset
                        </button>
                    </div>
                </div>

                {isMobile && (
                    <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                        <p className="text-sm text-blue-700">
                            <strong>Mobile OS Mode:</strong> Registers all callbacks (FCPreCreate, FCPostCreate,
                            FCPreRead, FCPostRead, FCPreWrite, FCPostWrite) for full encryption/decryption pipeline
                        </p>
                    </div>
                )}

                {!isMobile && (
                    <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                        <p className="text-sm text-yellow-700">
                            <strong>Desktop OS Mode:</strong> Registers only Create callbacks (FCPreCreate,
                            FCPostCreate) - Read/Write operations are not intercepted
                        </p>
                    </div>
                )}
            </div>


            {/* Architecture Diagram */}
            <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
                <h2 className="text-xl font-semibold mb-4">Driver Architecture & Flow</h2>
                <div
                    className="relative h-[600px] border-2 border-gray-200 rounded-lg bg-gradient-to-b from-gray-50 to-white">
                    {Object.entries(components).map(([id, component]) => (
                        <ComponentNode
                            key={id}
                            id={id}
                            isActive={isComponentActive(id)}
                            isSelected={selectedComponent === id}
                            onClick={onComponentClick}
                            isMobile={isMobile}
                            activeOperation={activeOperation}
                            animationStep={animationStep}
                            component={component}
                        />
                    ))}

                    {/* Flow indicators */}
                    {isAnimating && animationStep > 0 && (
                        <div className="absolute inset-0 pointer-events-none">
                            {operationFlows[activeOperation].slice(0, animationStep + 1).map((flow, idx) => {
                                if (idx === 0) return null;
                                const prevPos = getComponentPosition(operationFlows[activeOperation][idx - 1].component);
                                const currPos = getComponentPosition(flow.component);

                                return (
                                    <svg
                                        key={idx}
                                        className="absolute inset-0 w-full h-full"
                                        style={{zIndex: 5}}
                                    >
                                        <line
                                            x1={`${prevPos.x}%`}
                                            y1={`${prevPos.y}%`}
                                            x2={`${currPos.x}%`}
                                            y2={`${currPos.y}%`}
                                            stroke="#3b82f6"
                                            strokeWidth="3"
                                            strokeDasharray="5,5"
                                            className="animate-pulse"
                                        />
                                        <circle
                                            cx={`${currPos.x}%`}
                                            cy={`${currPos.y}%`}
                                            r="4"
                                            fill="#3b82f6"
                                            className="animate-ping"
                                        />
                                    </svg>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>

            {/* Component Details */}
            {selectedComponent && (
                <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
                    <div className="flex items-start gap-4">
                        <div className="flex-1">
                            <div className="flex items-center gap-3 mb-3">
                                <h3 className="text-xl font-semibold">{components[selectedComponent].title}</h3>
                                <span className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-sm font-mono">
                  {components[selectedComponent].file}
                </span>
                            </div>
                            <p className="text-gray-700 mb-4">{components[selectedComponent].description}</p>
                            <p className="text-gray-600 text-sm mb-4">{components[selectedComponent].details}</p>

                            <div>
                                <h4 className="font-semibold text-gray-800 mb-2">Key Functions:</h4>
                                <div className="flex flex-wrap gap-2">
                                    {components[selectedComponent].functions.map((func, idx) => (
                                        <span key={idx}
                                              className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm font-mono">
                      {func}()
                    </span>
                                    ))}
                                </div>
                            </div>
                        </div>
                        <button
                            onClick={() => setSelectedComponent(null)}
                            className="text-gray-400 hover:text-gray-600"
                        >
                            ×
                        </button>
                    </div>
                </div>
            )}

            {/* Footer */}
            <div className="mt-8 text-center text-gray-500 text-sm">
                <p>Academic Research Project - Windows Kernel Driver Analysis</p>
                <p className="mt-1">Decompiled from filtcrypt.sys using Ghidra</p>
            </div>
        </div>
    );
};

ReactDOM.createRoot(document.getElementById('root')).render(
    <FileCryptExplorer/>
);