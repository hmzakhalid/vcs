use alloy::{
    primitives::{address, Address, B256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::{BlockNumberOrTag, Filter, Log},
    sol, sol_types::SolEvent, transports::BoxTransport,
};
use eyre::Result;
use futures_util::stream::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::fmt::Debug;

pub trait BlockchainEvent: Send + Sync + 'static {
    fn process(&self) -> Result<()>;
}

impl<T> BlockchainEvent for T
where
    T: SolEvent + Debug + Send + Sync + 'static,
{
    fn process(&self) -> Result<()> {
        println!("Default processing: {:?}", self);
        Ok(())
    }
}

pub struct BlockchainEventListener {
    provider: Arc<RootProvider<BoxTransport>>,
    filter: Filter,
    decoders: HashMap<B256, Arc<dyn Fn(Log) -> Result<Box<dyn BlockchainEvent>> + Send + Sync>>,
}

impl BlockchainEventListener {
    pub fn new(provider: Arc<RootProvider<BoxTransport>>, filter: Filter) -> Self {
        Self {
            provider,
            filter,
            decoders: HashMap::new(),
        }
    }

    pub fn add_event_handler<E>(&mut self)
    where
        E: SolEvent + BlockchainEvent + 'static,
    {
        let signature_hash = E::SIGNATURE_HASH;
        let decoder = Arc::new(move |log: Log| -> Result<Box<dyn BlockchainEvent>> {
            let event = log.log_decode::<E>()?.inner.data;
            Ok(Box::new(event))
        });

        self.decoders.insert(signature_hash, decoder);
    }

    pub async fn listen(&self) -> Result<()> {
        let sub = self.provider.subscribe_logs(&self.filter).await?;
        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            if let Some(topic0) = log.topic0() {
                if let Some(decoder) = self.decoders.get(topic0) {
                    match decoder(log.clone()) {
                        Ok(event) => {
                            if let Err(err) = event.process() {
                                eprintln!("Error processing event: {:?}", err);
                            }
                        }
                        Err(err) => {
                            eprintln!("Error decoding log: {:?}", err);
                        }
                    }
                } else {
                    eprintln!("No handler found for topic: {:?}", topic0);
                }
            }
        }

        Ok(())
    }
}

pub struct EthManager {
    provider: Arc<RootProvider<BoxTransport>>,
}

impl EthManager {
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let provider = ProviderBuilder::new().on_builtin(rpc_url).await?;
        Ok(Self {
            provider: Arc::new(provider),
        })
    }

    pub fn add_contract_listener(&self, contract_address: Address) -> BlockchainEventListener {
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumberOrTag::Latest);

        BlockchainEventListener::new(self.provider.clone(), filter)
    }
}

sol! {
    #[derive(Debug)]
    event TestingEvent(uint256 e3Id, bytes input);
}

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_url = "ws://127.0.0.1:8545";

    let eth_manager = EthManager::new(rpc_url).await?;

    let contract_address1 = address!("e7f1725E7734CE288F8367e1Bb143E90bb3F0512");
    let mut listener1 = eth_manager.add_contract_listener(contract_address1);
    listener1.add_event_handler::<TestingEvent>();

    let contract_address2 = address!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    let mut listener2 = eth_manager.add_contract_listener(contract_address2);
    listener2.add_event_handler::<TestingEvent>();

    tokio::try_join!(listener1.listen(), listener2.listen())?;

    Ok(())
}
