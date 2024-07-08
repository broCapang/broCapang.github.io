

const HomePage = () => {

    return (
        <main className="flex-grow container mx-auto p-4">
            <section className="smy-8">
            <h1 className="text-4xl font-bold text-slate-200">Welcome to My Personal Website</h1>
            <p className="text-slate-200 mt-4">
                This site is a canvas for my writeups collection, portfolio, and contact information.
            </p>
            </section>
            <br />
            <section className="my-8">
            <h2 className="text-2xl font-bold text-slate-200">About This Website</h2>
            <p className="text-slate-200 mt-4">
                This website is a collection of my writeups, portfolio, and contact information.

            </p>
            </section>

            {/* Additional content sections can be added here */}
        </main>
    );
};

export default HomePage;
