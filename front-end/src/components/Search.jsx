

const Search = ({searchTerm,setSearchTerm,handlePrediction}) => {

  
  const handleSubmit = (event) => {
    event.preventDefault();
    
    handlePrediction(searchTerm);
    setSearchTerm('');
  }
  return (
    <div className="w-full border-1 rounded-3xl border-zinc-400 p-4 py-6">
      <form onSubmit={handleSubmit}>
        <input
          className="w-full h-full border-none focus:outline-none"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search URL to detect"
        />
      </form>
    </div>
  )
}

export default Search