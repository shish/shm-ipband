use shadow_rs::ShadowBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ShadowBuilder::builder().build()?;
    Ok(())
}
