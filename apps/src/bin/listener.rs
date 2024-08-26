use alloy::{
    primitives::{address, U256, B256},
    providers::{Provider, ProviderBuilder, RootProvider, WsConnect},
    pubsub::PubSubFrontend,
    rpc::types::{BlockNumberOrTag, Filter, Log},
    sol,
    sol_types::SolEvent,
};
use eyre::Result;
use futures_util::stream::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    EvenNumber,
    "out/EvenNumber.sol/EvenNumber.json"
);

pub trait BlockchainEvent: Sized + Send + Sync + 'static {
    fn decode(log: Log) -> Result<Self>;
    fn process(&self) -> Result<()>;
}

// The generic BlockchainEventListener.
pub struct BlockchainEventListener {
    provider: RootProvider<PubSubFrontend>,
    filter: Filter,
    handlers: HashMap<B256, Arc<dyn Fn(Log) + Send + Sync>>,
}

impl BlockchainEventListener {
    pub async fn new(rpc_url: &str, filter: Filter) -> Result<Self> {
        let ws = WsConnect::new(rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;
        Ok(Self {
            provider,
            filter,
            handlers: HashMap::new(),
        })
    }

    pub fn add_event_handler<E>(&mut self, signature_hash: B256)
    where
        E: BlockchainEvent,
    {
        let handler = Arc::new(move |log: Log| {
            if let Ok(event) = E::decode(log) {
                if let Err(err) = event.process() {
                    eprintln!("Error processing event: {:?}", err);
                }
            } else {
                eprintln!("Failed to decode event");
            }
        });

        self.handlers.insert(signature_hash, handler);
    }

    pub async fn listen(&self) -> Result<()> {
        let sub = self.provider.subscribe_logs(&self.filter).await?;
        let mut stream = sub.into_stream();

        while let Some(log) = stream.next().await {
            if let Some(topic0) = log.topic0() {
                if let Some(handler) = self.handlers.get(topic0) {
                    handler(log.clone());
                }
            }
        }

        Ok(())
    }
}

pub struct TestingEvent {
    pub e3Id: U256,
    pub input: Vec<u8>,
}

impl BlockchainEvent for TestingEvent {
    fn decode(log: Log) -> Result<Self> {
        let EvenNumber::Testing { e3Id , input} = log.log_decode().unwrap().inner.data;
        Ok(TestingEvent { e3Id, input: input.to_vec() })
    }

    fn process(&self) -> Result<()> {
        println!("Processing TestingEvent with e3Id = {}", self.e3Id);
        println!("Processing TestingEvent with Input = {:?}", self.input);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Set up the WS transport which is consumed by the RPC client.
    let rpc_url = "ws://127.0.0.1:8545";

    // Create a filter to watch for all EvenNumber contract events.
    let even_number_address = address!("e7f1725E7734CE288F8367e1Bb143E90bb3F0512");
    let filter = Filter::new()
        .address(even_number_address)
        .from_block(BlockNumberOrTag::Latest);

    // Create the event listener.
    let mut listener = BlockchainEventListener::new(rpc_url, filter).await?;

    // Register the event handler for the `Testing(uint256)` event.
    listener.add_event_handler::<TestingEvent>(EvenNumber::Testing::SIGNATURE_HASH);

    // Start listening for events.
    listener.listen().await?;

    Ok(())
}
