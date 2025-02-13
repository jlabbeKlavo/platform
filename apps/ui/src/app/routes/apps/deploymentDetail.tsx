import { FC, useEffect, useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import * as Tabs from '@radix-ui/react-tabs';
import * as Tooltip from '@radix-ui/react-tooltip';
import { UilLock, UilLockSlash, UilSpinner } from '@iconscout/react-unicons';
import { Utils } from '@secretarium/crypto';
import * as NivoGeo from '@nivo/geo';
import api from '../../utils/api';
import { formatTimeAgo } from '../../utils/formatTimeAgo';
import { DeploymentPromotion, DeploymentDeletion } from './deployments';
import RunCommand from '../../components/RunCommand';
import AttestationChecker from '../../components/AttestationChecker';
import { commitVerificationReasons } from '@klave/constants';
import geoFeatures from '../../geojson/ne_110m_admin_0_countries.json';

const { ResponsiveGeoMap } = NivoGeo;
const defaultNivoGeoProps = ((NivoGeo as unknown as Record<string, Record<string, unknown>>)?.GeoMapDefaultProps ?? {});

export const AppDeploymentDetail: FC = () => {

    const { deploymentId } = useParams();
    const [WASMFingerprint, setWASMFingerprint] = useState<string>();
    const { data: deployment, isLoading: isLoadingDeployments } = api.v0.deployments.getById.useQuery({ deploymentId: deploymentId || '' }, {
        refetchInterval: 5000
    });

    useEffect(() => {

        if (!deployment?.buildOutputWASM)
            return;

        crypto.subtle.digest('SHA-256', Utils.fromBase64(deployment.buildOutputWASM)).then((hash) => {
            setWASMFingerprint(Utils.toHex(new Uint8Array(hash)));
        }).catch(() => { return; });

    }, [deployment?.buildOutputWASM]);

    const datacentreMarkers = [{
        type: 'Feature',
        properties: {
            name: 'gandalf-3.ch-gre.int.klave.network',
            node: 'gandalf-3.ch-gre.int.klave.network',
            datacentre: 'Green Datacenter Lupig Zurich West 1 + 2',
            host: 'Green AG',
            plusCode: 'C6W6+QP Lupfig, Switzerland',
            country: 'Switzerland'
        },
        geometry: {
            type: 'Point',
            title: 'Green Datacenter Lupig Zurich West 1 + 2',
            coordinates: [
                8.211877948702393,
                47.44698358541104
            ]
        }
    }, {
        type: 'Feature',
        properties: {
            node: 'gimli-3.ch-gre.int.klave.network',
            datacentre: 'Green Datacenter Glattbrugg',
            host: 'Green AG',
            plusCode: '9FVV+5M Zürich, Switzerland',
            country: 'Switzerland'
        },
        geometry: {
            type: 'Point',
            coordinates: [
                8.559103756702704,
                47.43348161472324
            ]
        }
    }, {
        type: 'Feature',
        properties: {
            node: 'thranduil-3.ch-tin.int.klave.network',
            datacentre: 'DC-1 Tessin',
            host: 'Swisscolocation',
            plusCode: 'R2X7+7R Morbio Inferiore, Switzerland',
            country: 'Switzerland'
        },
        geometry: {
            type: 'Point',
            coordinates: [
                8.494152658580399,
                47.392958202883534
            ]
        }
    }];

    const centroid = datacentreMarkers.reduce((acc, f) => {
        if (f.geometry.type === 'Point')
            return [(f.geometry.coordinates[0] ?? 0) + (acc[0] ?? 0), (f.geometry.coordinates[1] ?? 0) + (acc[1] ?? 0), 0];
        return acc;
    }, [0, 0, 0]).map(v => -(v / datacentreMarkers.length)) as [number, number, number];

    const mapFeatures = useMemo(() => [...geoFeatures.features, ...datacentreMarkers].map((f, i) => {
        return {
            ...f,
            id: `f${i}`,
            properties: {
                ...f.properties,
                id: `f${i}`
            }
        };
    }), [geoFeatures.features, datacentreMarkers]);

    if (isLoadingDeployments || !deployment)
        return <>
            We are fetching data about your deployment.<br />
            It will only take a moment...<br />
            <br />
            <UilSpinner className='inline-block animate-spin' />
        </>;

    const { deploymentAddress, createdAt, expiresOn, life, status, version, build, branch, commit } = deployment;
    const hasExpired = new Date().getTime() > expiresOn.getTime();

    if (!deploymentAddress)
        return <>
            We experienced an issue fetching your deployment.<br />
        </>;

    const { fqdn } = deploymentAddress;
    const verification = commit?.verification;
    const { verified, reason } = verification || {};
    const badge = !verification ? null : verified
        ? <div className="badge badge-xs py-2 text-lime-500 border-lime-400"><UilLock className='h-3 w-3 mr-1' />{commitVerificationReasons[reason ?? 'unknown']}</div>
        : reason === 'unsigned'
            ? <div className="badge badge-xs py-2 text-slate-400 border-slate-500"><UilLockSlash className='h-3 w-3 mr-1' />{commitVerificationReasons[reason ?? 'unknown']}</div>
            : <div className="badge badge-xs py-2 text-red-400 border-red-400"><UilLockSlash className='h-3 w-3 mr-1' />{commitVerificationReasons[reason ?? 'unknown']}</div>;

    return <div className="flex flex-col w-full mb-7">
        <div className="flex w-full justify-between">
            <div className='mb-10'>
                <h2 className='font-bold mb-3'>Addresses of the honest application</h2>
                <span className='font-mono inline-block rounded dark:text-slate-400 dark:bg-slate-800 text-slate-900 bg-slate-100 px-2 py-1 mb-1 whitespace-nowrap'>{fqdn}</span><br />
                <span className={`rounded inline-block text-xs px-1 py-0 mr-2 text-white ${life === 'long' ? 'bg-green-600' : 'bg-slate-500'}`}>{life === 'long' ? 'Production' : 'Preview'}</span>
                <span className={`rounded inline-block text-xs px-1 py-0 text-white ${status === 'errored' ? 'bg-red-700' : status === 'deployed' ? 'bg-blue-500' : 'bg-stone-300'}`}>{status}</span>
            </div>
            <div className='mb-10 sm:block hidden'>
                <h2 className='font-bold mb-3'>Version</h2>
                <div className="flex items-center">
                    <div className="flex-col">
                        <span className='block'>{version ?? '-'}</span>
                        {build ? <span className={'block text-xs text-slate-500'}>{build}</span> : null}
                    </div>
                </div>
            </div>
            <div className='mb-10 sm:block hidden'>
                <h2 className='font-bold mb-3'>Location</h2>
                <div className="flex items-center">
                    <div className="flex flex-col">
                        <span className='block' title={createdAt.toDateString()}>Switzerland (CH)</span>
                        <Tooltip.Provider delayDuration={100}>
                            <Tooltip.Root>
                                <Tooltip.Trigger asChild>
                                    <span className={'block text-xs text-slate-500 hover:cursor-pointer'}>3 nodes</span>
                                </Tooltip.Trigger>
                                <Tooltip.Portal>
                                    <Tooltip.Content className="text-sm bg-slate-100 p-2 shadow" align='start' side="bottom">
                                        <ul>
                                            <li></li>
                                            <li></li>
                                            <li></li>
                                        </ul>
                                        <div className='w-96 h-60 bg-white'>
                                            <ResponsiveGeoMap
                                                {...defaultNivoGeoProps}
                                                features={mapFeatures}
                                                projectionRotation={centroid}
                                                projectionScale={6000}
                                                borderWidth={(feature) => {
                                                    if (feature.geometry?.type === 'Point')
                                                        return 0;
                                                    return 0.5;
                                                }}
                                                borderColor='#AAA'
                                                fillColor={(feature) => {
                                                    if (feature.geometry?.type === 'Point')
                                                        return '#F00';
                                                    return '#EEE';
                                                }}
                                                graticuleLineColor='#DDD'
                                                enableGraticule={true}
                                                isInteractive={true}
                                            />
                                        </div>
                                        <Tooltip.Arrow className="fill-slate-100" width={10} height={10} />
                                    </Tooltip.Content>
                                </Tooltip.Portal>
                            </Tooltip.Root>
                        </Tooltip.Provider>
                    </div>
                </div>
            </div>
            <div className='mb-10'>
                <h2 className='font-bold mb-3'>Creation time</h2>
                <div className="flex items-center">
                    <div className="flex-col">
                        <span className='block' title={createdAt.toDateString()}>{formatTimeAgo(createdAt)}</span>
                        {life === 'short' ? <span className={'block text-xs text-slate-500'}>{hasExpired ? 'Expired' : 'Expires'} {formatTimeAgo(expiresOn)}</span> : <span></span>}
                    </div>
                </div>
            </div>
        </div>
        <div className="flex w-full justify-between">
            <div className='mb-10'>
                <h2 className='font-bold mb-3'>Branch</h2>
                <div className="flex items-center">
                    <div className="sm:flex hidden flex-row align-middle gap-2 items-center">
                        <span className='font-mono inline rounded dark:text-slate-400 dark:bg-slate-800 text-slate-900 bg-slate-100 px-2 py-1 mb-1 whitespace-nowrap' title={!branch ? undefined : branch}>{branch?.replace('refs/heads/', '')}</span>
                        <span className='pb-1'>{badge}</span>
                    </div>
                </div>
            </div>
            <div className='mb-10'>
                <h2 className='font-bold mb-3'>Actions</h2>
                <div className='flex flex-row items-center'>
                    {status === 'deployed' || status === 'terminated' && life !== 'long' ? <>
                        <DeploymentPromotion deployment={deployment} />
                        &nbsp;&nbsp;
                    </> : null}
                    <DeploymentDeletion deployment={deployment} />
                </div>
            </div>
        </div>
        {status === 'deployed'
            ? <Tabs.Root defaultValue="inspect" className='flex flex-col w-full'>
                <Tabs.List className='flex flex-shrink-0 border-b'>
                    <Tabs.Trigger value="inspect" className='flex-1 border-0 border-b-2 border-transparent rounded-none data-[state=active]:border-klave-light-blue shadow-none text-sm font-normal text-gray-600 dark:text-gray-400 hover:text-klave-light-blue data-[state=active]:font-bold data-[state=active]:text-klave-light-blue'>Inspect</Tabs.Trigger>
                    <Tabs.Trigger value="dependencies" className='flex-1 border-0 border-b-2 border-transparent rounded-none data-[state=active]:border-klave-light-blue shadow-none text-sm font-normal text-gray-600 dark:text-gray-400 hover:text-klave-light-blue data-[state=active]:font-bold data-[state=active]:text-klave-light-blue'>Dependencies</Tabs.Trigger>
                    <Tabs.Trigger value="attest" className='flex-1 border-0 border-b-2 border-transparent rounded-none data-[state=active]:border-klave-light-blue shadow-none text-sm font-normal text-gray-600 dark:text-gray-400 hover:text-klave-light-blue data-[state=active]:font-bold data-[state=active]:text-klave-light-blue'>Attest</Tabs.Trigger>
                </Tabs.List>
                <Tabs.Content value="inspect">
                    <div className='mt-10'>
                        <RunCommand address={fqdn} functions={deployment.contractFunctions} />
                    </div>
                    <div className='mt-10'>
                        <h2 className='font-bold mb-3'>Code Explorer</h2>
                        <h3 className='mb-3'>Type declarations</h3>
                        <pre className='overflow-auto whitespace-pre-wrap break-words w-full max-w-full bg-slate-100 dark:bg-gray-800 p-3'>
                            {deployment.buildOutputDTS}
                        </pre>
                        <h3 className='mt-5 mb-3'>WASM</h3>
                        <pre className='overflow-auto whitespace-pre-wrap break-words w-full max-w-full bg-slate-100 dark:bg-gray-800 p-3'>
                            SHA256:{WASMFingerprint}
                        </pre>
                        <pre className='overflow-auto whitespace-pre-wrap break-words w-full max-w-full max-h-[50vh] bg-slate-100 dark:bg-gray-800 p-3 mt-2'>
                            {deployment.buildOutputWASM}
                        </pre>
                    </div>
                </Tabs.Content>
                <Tabs.Content value="dependencies">
                    <div className='mt-10'>
                        <h2 className='font-bold mb-3'>List of external dependencies and digests</h2>
                        <pre className='overflow-auto whitespace-pre-wrap break-words w-full max-w-full bg-gray-100 p-3'>
                            {JSON.stringify(deployment.dependenciesManifest, null, 4)}
                        </pre>
                    </div>
                </Tabs.Content>
                <Tabs.Content value="attest">
                    <div className='mt-10'>
                        <AttestationChecker deploymentId={deployment.id} address={fqdn} />
                    </div>
                </Tabs.Content>
            </Tabs.Root>
            : status === 'errored'
                ? <Tabs.Root defaultValue="inspect" className='flex flex-col w-full'>
                    <Tabs.List className='flex flex-shrink-0 border-b'>
                        <Tabs.Trigger value="inspect" className='flex-1 border-0 border-b-2 border-transparent rounded-none data-[state=active]:border-klave-light-blue shadow-none text-sm font-normal text-gray-600 dark:text-gray-400 hover:text-klave-light-blue data-[state=active]:font-bold data-[state=active]:text-klave-light-blue'>Inspect</Tabs.Trigger>
                        <Tabs.Trigger value="dependencies" className='flex-1 border-0 border-b-2 border-transparent rounded-none data-[state=active]:border-klave-light-blue shadow-none text-sm font-normal text-gray-600 dark:text-gray-400 hover:text-klave-light-blue data-[state=active]:font-bold data-[state=active]:text-klave-light-blue'>Dependencies</Tabs.Trigger>
                    </Tabs.List>
                    <Tabs.Content value="inspect">
                        <div className='mt-10'>
                            <h2 className='font-bold mb-3'>Errors reported during compilation</h2>
                            <pre className='overflow-auto whitespace-pre-wrap break-words w-full max-w-full bg-red-100 p-3'>
                                {(deployment.buildOutputErrorObj as unknown as Error)?.stack ?? JSON.stringify(deployment.buildOutputErrorObj ?? {}, null, 4)}<br />
                                {(deployment.buildOutputStdErr)}
                            </pre>
                        </div>
                    </Tabs.Content>
                    <Tabs.Content value="dependencies">
                        <div className='mt-10'>
                            <h2 className='font-bold mb-3'>List of external dependencies and digests</h2>
                            <pre className='overflow-auto whitespace-pre-wrap break-words w-full max-w-full bg-gray-100 p-3'>
                                {JSON.stringify(deployment.dependenciesManifest, null, 4)}
                            </pre>
                        </div>
                    </Tabs.Content>
                </Tabs.Root>
                : null}
    </div >;
};

export default AppDeploymentDetail;