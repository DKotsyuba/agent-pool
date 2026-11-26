//! Stable display vocabulary and name derivation for Pool chat seats.

use sha2::{Digest, Sha256};

/// First words in stable index order. Reordering changes existing display names.
const ADJECTIVES: &str = "\
Amber Azure Alpine Analog Arctic Astral Auburn Autumn Avid Balsam
Baltic Beaded Blooming Blue Bold Boreal Breezy Bright Brisk Bronze
Brown Brushed Calm Celadon Centered Cherry Chilled Chiming Circular Classic
Clear Coastal Cobalt Compact Cool Copper Coral Cosmic Crisp Curved
Dappled Deep Delicate Dewy Digital Distant Dry Dusky Early Earthy
Eastern Edged Elastic Emerald Even Faint Fine Floral Flowing Foggy
Folded Fractal Fresh Frosted Frozen Fuzzy Gentle Gilded Glassy Glossy
Golden Grassy Green Guided Hazel Hazy Hidden Icy Inner Ivory
Jade Keen Khaki Kind Laced Leafy Level Light Lilac Linear
Lively Local Lofty Long Lunar Lush Lustrous Marble Marine Matte
Mellow Misty Modest Mosaic Mossy Muted Narrow Near Neat Nimble
Noble Northern Ochre Olive Onyx Opal Open Orange Orchid Outer
Pacific Pale Pastel Peach Pearly Pebbled Pink Plain Placid Plum
Plush Polished Quiet Rapid Remote Rich Ridged Rippled Rocky Rolling
Rosy Round Ruby Rusty Sandy Satin Scarlet Shaded Shiny Silky
Silver Simple Slate Sleek Slim Smooth Snowy Soft Solar Solid
Southern Spherical Spotted Spring Starlit Steady Steel Stellar Still Striped
Subtle Summer Sunny Swift Tawny Teal Tender Thin Tidal Tinted
Topaz Traced Trim Umber Velvet Vivid Warm Wavy Western White
Wild Willow Windy Winter Wispy Woven Yellow Young Zesty";

/// Second words in stable index order. Reordering changes existing display names.
const NOUNS: &str = "\
Acorn Alder Alpaca Anchor Apricot Arbor Arch Aspen Aster Avocet
Badger Barn Basin Bay Beacon Bee Beech Bell Bison Bloom
Boulder Bramble Branch Breeze Brook Buffalo Cabin Cairn Canary Candle
Canoe Canyon Carp Cat Cave Chime Circle Cliff Cloud Clover
Coast Comet Cone Cove Crane Creek Crest Cricket Crocus Cube
Cypress Dahlia Daisy Deer Delta Dew Dome Dove Drum Dune
Eagle Echo Elm Falcon Fennel Finch Fir Fjord Flame Flute
Foal Fog Fox Frond Frost Gable Gale Garden Gate Gazelle
Geode Glade Globe Grove Gull Harbor Hare Harp Hawk Heron
Hill Hive Holly Horizon Iris Isle Ivy Jay Juniper Kestrel
Kite Knoll Lagoon Lake Larch Lark Laurel Leaf Lens Lichen
Lily Llama Magpie Maple Marsh Meadow Mesa Minnow Moon Moss
Moth Nest Newt Oak Oat Osprey Otter Owl Palm Panda
Park Path Pearl Pebble Petal Pine Plover Pond Poppy Porch
Prism Quail Quartz Quill Rabbit Rain Raven Reed Reef Ridge
Robin Rock Root Rowan Sail Sand Seal Seed Shade Shell
Shore Shrub Siskin Skiff Sky Slope Snow Sparrow Sprig Sprout
Stag Star Stem Stilt Stoat Stone Stork Stream Summit Swan
Swift Tern Thyme Tide Trout Tulip Vale Vetch Vine Vista
Wave Web Wheat Wing Wren Yak Yew Zebra Zinnia";

/// Derives a stable display name from a pool and its seat's immutable member ID.
pub(super) fn generated_name(pool_id: &str, member_id: &str) -> String {
    let digest = Sha256::digest(format!("{pool_id}/{member_id}").as_bytes());
    let adjective = word_at(
        ADJECTIVES,
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]),
    );
    let noun = word_at(
        NOUNS,
        u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]]),
    );
    format!("{adjective} {noun}")
}

/// Selects one word by reducing an index modulo the vocabulary length.
fn word_at(words: &str, index: u32) -> &str {
    let count = words.split_ascii_whitespace().count();
    words
        .split_ascii_whitespace()
        .nth(index as usize % count)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::generated_name;

    /// Matches Bridge's sender names for the same three input strings.
    #[test]
    fn bridge_name_parity() {
        assert_eq!(
            generated_name("example", "claude/default/session"),
            "Shaded Snow"
        );
        assert_eq!(
            generated_name("example", "codex/default/session"),
            "Elastic Glade"
        );
        assert_eq!(generated_name("pool-a", "member-1"), "Beaded Cube");
    }
}
